<?php

/**
 * Paquete de evidencia autocontenido (§19.3).
 *
 * Requisito R1: todo lo necesario para verificar, sin conexión y sin preguntar
 * al nodo que lo produjo. Si verificar depende de la colaboración del operador,
 * lo que tiene la parte débil no es evidencia: es una solicitud.
 *
 * Dos campos van deliberadamente vacíos y dicen por qué: `certificates` y
 * `revocation_status`. Este demostrador fija identidades al primer uso (la §5.3
 * quiere una cadena de certificados) y no tiene responder OCSP, y la §19.3 es
 * explícita en que una respuesta de revocación debe llevar *la fecha del
 * hecho*, no la de hoy. Escribir ahí "vigente" sin una respuesta firmada de
 * entonces sería justo el error más común en evidencia electrónica, así que el
 * campo se queda vacío y declara su ausencia.
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/journal.php';
require_once __DIR__ . '/epoch.php';
require_once __DIR__ . '/receipt.php';
require_once __DIR__ . '/transparency.php';

/**
 * @param string $rcHashHex Hash del receipt_core que se reclama
 * @param string|null $payload Texto en claro, cuando quien exporta quiere que el
 *                             paquete pruebe el contenido y no solo la entrega
 *
 * @throws RuntimeException Si este nodo no conserva registro de ese recibo
 *
 * @return array<string, mixed>
 */
function buildEvidencePackage($rcHashHex, $payload = null)
{
    $record = receiptRecordLoad('srv', $rcHashHex);

    if ($record === null) {
        throw new RuntimeException('Este nodo no conserva ningún registro de recibo para ' . $rcHashHex);
    }

    $epoch = (int) $record['epoch'];
    $proof = epochProofFor($epoch, $rcHashHex);
    $epochRecord = epochRecord($epoch);
    $checkpoint = journalCheckpointCovering('srv', (int) $record['journal_n']);
    $core = (array) $record['core'];

    $package = [
        'qslp_evidence' => 1,
        'spec_version' => 'QSLP/1',
        'claim' => evidenceClaim($core),
        'receipt_core' => $core,
        'receipt_core_hash' => (string) $record['core_hash'],
        'payload' => evidencePayload($core, $payload),
        'signatures' => [
            'sender' => [
                'node_id' => (string) $core['from'],
                'sig_alg' => SIG_ALG,
                'domain' => RECEIPT_DOMAIN,
                'signature' => (string) $record['sender_signature'],
            ],
            'receiver_receipt' => $record['receipt'],
        ],
        'identities' => [
            'sender' => [
                'node_id' => (string) $core['from'],
                'sig_alg' => SIG_ALG,
                'public_key' => (string) $record['sender_identity'],
            ],
            'receiver' => [
                'node_id' => (string) $core['to'],
                'sig_alg' => SIG_ALG,
                'public_key' => (string) $record['receiver_identity'],
            ],
            'trust' => 'Identidades fijadas al primer uso (trust on first use). No hay cadena de '
                . 'certificados: la §5.3 la exige y este demostrador no la implementa, así que la '
                . 'confianza en estas claves depende de cómo se fijaron, no de una autoridad.',
        ],
        'certificates' => [],
        'certificates_absent' => 'No implementado: la §5.3 (certificados) y la §5.4 (revocación) '
            . 'quedan fuera del paso 5. Las claves públicas van en claro en "identities".',
        'revocation_status' => [],
        'revocation_absent' => 'No implementado: la §19.3 exige la respuesta OCSP firmada con la '
            . 'fecha del hecho, no la de hoy. Sin responder OCSP, afirmar "vigente" sería inventarlo.',
        'timestamp' => $epochRecord === null ? null : $epochRecord['timestamp'],
        'merkle_proof' => $proof,
        'checkpoint' => $checkpoint,
        'consistency_proof' => $checkpoint === null ? null : journalConsistencyProof('srv', $checkpoint),
        'anchor' => $epochRecord === null ? null : $epochRecord['anchor'],
        'journal_entry' => [
            'side' => 'srv',
            'n' => (int) $record['journal_n'],
            'entry' => $record['journal_entry'],
        ],
        // Demuestra que esa entrada pertenece al diario que el nodo firmó, sin
        // entregar el resto del diario.
        'journal_proof' => $checkpoint === null
            ? null
            : journalInclusionProof('srv', (int) $record['journal_n'], (int) $checkpoint['n']),
        // Lo que el paso 6 añade: la raíz de la época no solo está anclada en
        // el diario del propio nodo, sino publicada en un log con identidad
        // distinta, y el paquete trae con qué comprobarlo sin preguntar a
        // nadie (§12).
        'transparency' => $epochRecord === null ? null : ($epochRecord['transparency'] ?? null),
        'log_checkpoint' => logLastCheckpoint(),
        // Ata la raíz contra la que se hizo la prueba de inclusión con el
        // último checkpoint firmado del log: sin esto, la inclusión demuestra
        // que la época consta en *alguna* vista del log, no en la vigente.
        'log_consistency' => evidenceLogConsistency($epochRecord),
        'log_identity' => evidenceLogIdentity(),
        // Y la otra mitad de la §19.5: que no consta ningún acto de autoridad
        // contra ninguno de los dos extremos. Es la prueba de no ocurrencia.
        'authority_acts' => [
            'sender' => actsProofFor((string) $core['from']),
            'receiver' => actsProofFor((string) $core['to']),
        ],
        'crypto_provenance' => cryptoProvenance(),
        'exported_at' => rfc3339(),
    ];

    if ($proof === null || $epochRecord === null) {
        $package['incomplete'] = 'La época ' . $epoch . ' todavía no está anclada: sin raíz anclada no '
            . 'hay prueba de inclusión. Cierra la época y vuelve a exportar.';
    }

    return $package;
}

/**
 * Prueba de consistencia entre el árbol que usó la prueba de inclusión de la
 * época y el tamaño del último checkpoint.
 *
 * @param array|null $epochRecord
 *
 * @return array<string, mixed>|null
 */
function evidenceLogConsistency($epochRecord)
{
    if (!is_array($epochRecord) || !isset($epochRecord['transparency']['inclusion']['tree_size'])) {
        return null;
    }

    return logConsistencyProof((int) $epochRecord['transparency']['inclusion']['tree_size']);
}

/**
 * Identidad pública del log, para que el paquete se pueda verificar sin pedirle
 * nada a nadie.
 *
 * Va acompañada de su advertencia: una clave que viaja dentro del paquete que
 * se está verificando no demuestra de quién es. Hay que compararla con la que
 * se conozca por otra vía, y para eso el verificador acepta --log-id.
 *
 * @return array<string, mixed>|null
 */
function evidenceLogIdentity()
{
    $publicKey = logPublicKey();

    if ($publicKey === null) {
        return null;
    }

    return [
        'log_id' => nodeId($publicKey),
        'sig_alg' => SIG_ALG,
        'public_key' => b64uEncode($publicKey),
        'fingerprint' => identityFingerprint($publicKey),
        'warning' => 'Esta clave viaja dentro del propio paquete: compárala con la del log que '
            . 'conozcas por otra vía antes de darle valor.',
    ];
}

/**
 * La afirmación en lenguaje llano, para quien tenga que leer esto sin ser
 * criptógrafo (§19.4, punto 4).
 *
 * @param array $core
 *
 * @return string
 */
function evidenceClaim(array $core)
{
    return sprintf(
        'El nodo %s envió al nodo %s el mensaje nº %d de la sesión %s el %s, '
        . 'con contenido cuyo SHA3-256 es %s.',
        $core['from'],
        $core['to'],
        (int) $core['seq'],
        $core['sid'],
        $core['ts'],
        $core['payload_hash'],
    );
}

/**
 * La §19.3 admite el texto en claro o su ausencia justificada. Los dos casos se
 * declaran expresamente, porque quien lea el paquete no debería tener que
 * adivinar cuál de los dos tiene delante.
 *
 * @param array $core
 * @param string|null $payload
 *
 * @return array<string, mixed>
 */
function evidencePayload(array $core, $payload)
{
    if ($payload === null || $payload === '') {
        return [
            'present' => false,
            'reason' => 'El nodo no almacena el texto en claro (§15.2). El campo payload_hash de '
                . 'receipt_core lo ata: quien conserve el mensaje puede demostrar que es ése.',
            'payload_hash' => (string) $core['payload_hash'],
        ];
    }

    return [
        'present' => true,
        'encoding' => 'base64url',
        'value' => b64uEncode($payload),
        'payload_hash' => (string) $core['payload_hash'],
        'matches_hash' => hash_equals((string) $core['payload_hash'], hash('sha3-256', $payload)),
    ];
}

/**
 * Qué implementación exacta produjo estas firmas (§19.8).
 *
 * Sin esto, una verificación que falle dentro de cinco años no se puede
 * distinguir de una firma que nunca fue válida.
 *
 * @return array<string, mixed>
 */
function cryptoProvenance()
{
    $liboqs = @file_get_contents('/etc/liboqs-version');

    return [
        'liboqs' => $liboqs === false ? 'desconocida' : trim($liboqs),
        'oqsphp' => phpversion('oqsphp') ?: 'desconocida',
        'php' => PHP_VERSION,
        'commit' => trim((string) getenv('QSLP_BUILD_COMMIT')) ?: 'desconocido',
        'suite' => 'ML-KEM-768 + ML-DSA-65 + AES-256-GCM, SHA3-256',
        'suite_note' => 'No es la suite obligatoria de la §4.1, que exige híbrido clásico + '
            . 'post-cuántico (X25519 y Ed25519 junto a ML-KEM y ML-DSA). Falta la mitad clásica.',
        'canonicalization' => 'Subconjunto de JCS (RFC 8785): objetos, listas, cadenas, enteros, '
            . 'booleanos y null; los flotantes se rechazan en lugar de formatearse a mano.',
    ];
}
