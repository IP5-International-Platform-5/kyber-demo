<?php

/**
 * Log de transparencia (§12), con su propio rol y su propia identidad.
 *
 * «P1 no se cumple publicando una web. Se cumple con registros verificables.»
 * El paso 5 dejó la evidencia en manos del nodo central, que es precisamente el
 * adversario A4: el servidor que miente, censura o emite en secreto. Un
 * registro que custodia y firma el propio auditado no sirve contra él, así que
 * el log es un rol aparte con claves propias.
 *
 * Honestidad sobre el montaje: en este demostrador el log corre en la misma
 * máquina que todo lo demás. La separación es de claves y de código, no física.
 * Lo que sí consigue es que el nodo central **no pueda fabricar checkpoints del
 * log**, que es la propiedad de la que depende todo lo demás.
 *
 * Qué va dentro, como hojas de un árbol de Merkle append-only:
 *
 *   identity       una identidad publicada. Sustituye al log de certificados de
 *                  la §12.1 mientras no haya CA: el efecto que importa es el
 *                  mismo, que nadie pueda presentar una identidad que no consta.
 *   authority_act  todo acto con efectos sobre un nodo (§12.2), con motivo,
 *                  evidencia y autor. Un bloqueo que no aparece aquí es
 *                  inválido, y el código lo trata como tal.
 *   epoch_root     la raíz de cada época de recibos (§11.4), para que el
 *                  anclaje quede también fuera del nodo que lo produce.
 *   epoch_gap      un hueco declarado en la numeración de épocas. La §19.5
 *                  exige continuidad; cuando el servicio ha estado parado, el
 *                  hueco se firma en lugar de dejarlo en silencio.
 *
 * Los actos se indexan además en un árbol disperso por sujeto, que es lo que
 * permite demostrar que **no** hay ningún acto contra un nodo (§19.5).
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/merkle.php';
require_once __DIR__ . '/sparse_merkle.php';
require_once __DIR__ . '/identity.php';

if (!defined('TRANSPARENCY_DIR')) {
    define('TRANSPARENCY_DIR', __DIR__ . '/../transparency');
}

if (!defined('LOG_LEAF_DOMAIN')) {
    define('LOG_LEAF_DOMAIN', 'QSLP1-demo TL');
}

if (!defined('LOG_CHECKPOINT_DOMAIN')) {
    define('LOG_CHECKPOINT_DOMAIN', 'QSLP1-demo TLCP');
}

if (!defined('LOG_INCLUSION_DOMAIN')) {
    define('LOG_INCLUSION_DOMAIN', 'QSLP1-demo TLSCT');
}

/**
 * Tipos de hoja admitidos. Lista cerrada: una hoja de un tipo que nadie
 * entiende es material firmado que ninguna comprobación mira.
 */
if (!defined('LOG_LEAF_TYPES')) {
    define('LOG_LEAF_TYPES', 'identity,authority_act,epoch_root,epoch_gap');
}

/**
 * @return void
 */
function logEnsureDir()
{
    if (!is_dir(TRANSPARENCY_DIR) && !@mkdir(TRANSPARENCY_DIR, 0755, true) && !is_dir(TRANSPARENCY_DIR)) {
        throw new RuntimeException('No se puede crear el directorio del log: ' . TRANSPARENCY_DIR);
    }
}

/**
 * @return string
 */
function logPath()
{
    return TRANSPARENCY_DIR . '/log.jsonl';
}

/**
 * @return string
 */
function logCheckpointPath()
{
    return TRANSPARENCY_DIR . '/checkpoints.jsonl';
}

/**
 * @return string
 */
function logSubjectsPath()
{
    return TRANSPARENCY_DIR . '/subjects.json';
}

/**
 * Hash de una hoja, sobre su serialización canónica y con su propia etiqueta de
 * dominio, para que no se pueda confundir con una entrada de diario ni con un
 * nodo interno del árbol.
 *
 * @param array $leaf
 *
 * @return string 64 caracteres hexadecimales
 */
function logLeafHash(array $leaf)
{
    return hash('sha3-256', LOG_LEAF_DOMAIN . canonicalJson($leaf));
}

/**
 * @return array<int, array> Hojas en el orden en que se publicaron
 */
function logLeaves()
{
    $path = logPath();

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    if ($text === false) {
        return [];
    }

    $leaves = [];

    foreach (explode("\n", $text) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $leaf = json_decode($line, true);
        if (is_array($leaf)) {
            $leaves[] = $leaf;
        }
    }

    return $leaves;
}

/**
 * @return int Número total de entradas: el contador que la §19.5 exige firmar
 */
function logSize()
{
    return count(logLeaves());
}

/**
 * @return string[] Hashes de las hojas, en orden
 */
function logLeafHashes()
{
    $hashes = [];

    foreach (logLeaves() as $leaf) {
        $hashes[] = logLeafHash($leaf);
    }

    return $hashes;
}

/**
 * @param int|null $size Tamaño del árbol; por omisión, el actual
 *
 * @return string Raíz en hexadecimal, o la raíz del árbol vacío
 */
function logRoot($size = null)
{
    $hashes = logLeafHashes();

    if ($size !== null) {
        $hashes = array_slice($hashes, 0, (int) $size);
    }

    return empty($hashes) ? merkleEmptyRoot() : merkleRoot($hashes);
}

/**
 * Publica una hoja y devuelve su prueba de inclusión firmada.
 *
 * La prueba firmada es el equivalente del `sct` de la §12.1: lo que permite a
 * quien recibe una identidad exigir que conste en el log antes de aceptarla.
 *
 * @param string $type Uno de LOG_LEAF_TYPES
 * @param array $body Contenido de la hoja; solo hashes, identificadores y claves públicas
 * @param string|null $subject node_id al que afecta, si aplica
 *
 * @return array{leaf: array, seq: int, inclusion: array}
 */
function logAppend($type, array $body, $subject = null)
{
    if (!in_array($type, explode(',', LOG_LEAF_TYPES), true)) {
        throw new InvalidArgumentException('Tipo de hoja desconocido: ' . $type);
    }

    logEnsureDir();
    $path = logPath();
    $handle = @fopen($path, 'c+');

    if ($handle === false) {
        throw new RuntimeException('No se puede abrir el log para escribir: ' . $path);
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('No se puede bloquear el log: ' . $path);
        }

        $existing = [];
        $text = stream_get_contents($handle);

        foreach (explode("\n", (string) $text) as $line) {
            $line = trim($line);
            if ($line !== '') {
                $decoded = json_decode($line, true);
                if (is_array($decoded)) {
                    $existing[] = $decoded;
                }
            }
        }

        $leaf = [
            'seq' => count($existing),
            'type' => (string) $type,
            'ts' => rfc3339(),
            'subject' => $subject === null ? null : (string) $subject,
            'body' => $body,
        ];

        fseek($handle, 0, SEEK_END);

        if (fwrite($handle, canonicalJson($leaf) . "\n") === false) {
            throw new RuntimeException('No se puede escribir en el log: ' . $path);
        }

        fflush($handle);
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    return [
        'leaf' => $leaf,
        'seq' => (int) $leaf['seq'],
        'inclusion' => logInclusionProof((int) $leaf['seq']),
    ];
}

/**
 * Prueba de inclusión de una hoja, firmada por el log.
 *
 * @param int $seq
 *
 * @throws RuntimeException Si esa posición no existe
 *
 * @return array<string, mixed>
 */
function logInclusionProof($seq)
{
    $seq = (int) $seq;
    $hashes = logLeafHashes();

    if ($seq < 0 || $seq >= count($hashes)) {
        throw new RuntimeException('El log no tiene ninguna entrada en la posición ' . $seq);
    }

    $identity = loadOrCreateIdentity('log');

    $body = [
        'leaf_hash' => $hashes[$seq],
        'root' => merkleRoot($hashes),
        'seq' => $seq,
        'tree_size' => count($hashes),
    ];

    return $body + [
        'path' => merkleProof($hashes, $seq),
        'log_id' => nodeId($identity['public']),
        'sig_alg' => SIG_ALG,
        'signature' => b64uEncode(signDomain($identity['private'], LOG_INCLUSION_DOMAIN, canonicalJson($body))),
    ];
}

/**
 * Comprueba una prueba de inclusión: la firma del log y que el camino pliegue
 * hasta la raíz que esa misma firma cubre.
 *
 * @param array $inclusion
 * @param string $logPublicKey Clave pública ML-DSA del log
 * @param array|null $leaf Hoja que se quiere ver incluida
 *
 * @return bool
 */
function logVerifyInclusion($inclusion, $logPublicKey, ?array $leaf = null)
{
    if (!is_array($inclusion)) {
        return false;
    }

    foreach (['leaf_hash', 'root', 'seq', 'tree_size', 'path', 'signature'] as $field) {
        if (!isset($inclusion[$field])) {
            return false;
        }
    }

    if ($leaf !== null && !hash_equals(logLeafHash($leaf), strtolower((string) $inclusion['leaf_hash']))) {
        return false;
    }

    $signature = b64uDecode((string) $inclusion['signature']);

    if ($signature === false) {
        return false;
    }

    $body = [
        'leaf_hash' => strtolower((string) $inclusion['leaf_hash']),
        'root' => strtolower((string) $inclusion['root']),
        'seq' => (int) $inclusion['seq'],
        'tree_size' => (int) $inclusion['tree_size'],
    ];

    if (!verifyDomain($logPublicKey, LOG_INCLUSION_DOMAIN, canonicalJson($body), $signature)) {
        return false;
    }

    return merkleVerify($body['leaf_hash'], (array) $inclusion['path'], $body['root']);
}

/**
 * Firma y publica un checkpoint del log.
 *
 * Lleva número de secuencia y el contador total de entradas (§12.3, §19.5):
 * suprimir una entrada obliga a falsear un contador que ya está firmado, y
 * retroceder el tamaño es detectable sin más que comparar dos checkpoints.
 * Incluye también la raíz del árbol de actos, para que las pruebas de no
 * inclusión cuelguen de algo firmado.
 *
 * @return array<string, mixed>
 */
function logCheckpoint()
{
    logEnsureDir();
    $identity = loadOrCreateIdentity('log');
    $previous = logLastCheckpoint();

    $body = [
        'acts_root' => actsRoot(),
        'root' => logRoot(),
        'seq' => $previous === null ? 0 : ((int) $previous['seq'] + 1),
        'tree_size' => logSize(),
        'ts' => rfc3339(),
    ];

    $checkpoint = $body + [
        'log_id' => nodeId($identity['public']),
        'sig_alg' => SIG_ALG,
        'signature' => b64uEncode(signDomain($identity['private'], LOG_CHECKPOINT_DOMAIN, canonicalJson($body))),
    ];

    if (@file_put_contents(logCheckpointPath(), canonicalJson($checkpoint) . "\n", FILE_APPEND | LOCK_EX) === false) {
        throw new RuntimeException('No se puede escribir el checkpoint del log: ' . logCheckpointPath());
    }

    return $checkpoint;
}

/**
 * @return array<int, array>
 */
function logCheckpoints()
{
    $path = logCheckpointPath();

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    if ($text === false) {
        return [];
    }

    $checkpoints = [];

    foreach (explode("\n", $text) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $decoded = json_decode($line, true);
        if (is_array($decoded)) {
            $checkpoints[] = $decoded;
        }
    }

    return $checkpoints;
}

/**
 * @return array|null
 */
function logLastCheckpoint()
{
    $checkpoints = logCheckpoints();

    return empty($checkpoints) ? null : $checkpoints[count($checkpoints) - 1];
}

/**
 * @param array $checkpoint
 * @param string $logPublicKey
 *
 * @return bool
 */
function logVerifyCheckpoint($checkpoint, $logPublicKey)
{
    if (!is_array($checkpoint)) {
        return false;
    }

    foreach (['acts_root', 'root', 'seq', 'tree_size', 'ts', 'signature'] as $field) {
        if (!isset($checkpoint[$field])) {
            return false;
        }
    }

    $signature = b64uDecode((string) $checkpoint['signature']);

    if ($signature === false) {
        return false;
    }

    $body = [
        'acts_root' => strtolower((string) $checkpoint['acts_root']),
        'root' => strtolower((string) $checkpoint['root']),
        'seq' => (int) $checkpoint['seq'],
        'tree_size' => (int) $checkpoint['tree_size'],
        'ts' => (string) $checkpoint['ts'],
    ];

    return verifyDomain($logPublicKey, LOG_CHECKPOINT_DOMAIN, canonicalJson($body), $signature);
}

/**
 * Prueba de consistencia entre un tamaño anterior y el actual.
 *
 * @param int $size Tamaño del árbol antiguo
 *
 * @return array<string, mixed>|null
 */
function logConsistencyProof($size)
{
    $size = (int) $size;
    $hashes = logLeafHashes();

    if ($size < 1 || $size > count($hashes)) {
        return null;
    }

    return [
        'from_size' => $size,
        'to_size' => count($hashes),
        'from_root' => merkleRoot(array_slice($hashes, 0, $size)),
        'to_root' => merkleRoot($hashes),
        'proof' => merkleConsistencyProof($hashes, $size),
    ];
}

/**
 * Compara dos checkpoints firmados del mismo log y dice si prueban una vista
 * dividida (§12.3).
 *
 * Es la pieza más importante de la sección y la defensa concreta contra A4: una
 * autoridad puede mostrar vistas distintas del log a distintos usuarios, y
 * ningún observador aislado lo notaría. Dos checkpoints firmados que no encajan
 * son una prueba que cualquiera puede presentar, porque las firmas son del
 * propio log.
 *
 * El veredicto que importa no es «iguales o distintos» —el log crece, es normal
 * que difieran—, sino si el pequeño es prefijo del grande. Si no lo es, el log
 * se contradijo.
 *
 * @param array $a Un checkpoint firmado
 * @param array $b Otro checkpoint firmado
 * @param string $logPublicKey Clave pública del log
 * @param array|null $consistency Prueba de consistencia aportada, si hay
 *
 * @return array<string, mixed>
 */
function logCompareCheckpoints($a, $b, $logPublicKey, ?array $consistency = null)
{
    $result = [
        'both_signed' => false,
        'same_view' => null,
        'split_view' => false,
        'detail' => '',
    ];

    if (!logVerifyCheckpoint($a, $logPublicKey) || !logVerifyCheckpoint($b, $logPublicKey)) {
        $result['detail'] = 'Al menos uno de los dos checkpoints no está firmado por este log: '
            . 'sin firma no prueba nada, ni a favor ni en contra.';

        return $result;
    }

    $result['both_signed'] = true;
    $small = (int) $a['tree_size'] <= (int) $b['tree_size'] ? $a : $b;
    $large = $small === $a ? $b : $a;

    if ((int) $small['tree_size'] === (int) $large['tree_size']) {
        $same = hash_equals(strtolower((string) $small['root']), strtolower((string) $large['root']));
        $result['same_view'] = $same;
        $result['split_view'] = !$same;
        $result['detail'] = $same
            ? 'Mismo tamaño y misma raíz: la misma vista del log.'
            : 'Mismo tamaño (' . (int) $small['tree_size'] . ') y raíces distintas, las dos firmadas '
                . 'por el log: es una vista dividida, y estos dos checkpoints la demuestran.';

        return $result;
    }

    if ($consistency === null) {
        $result['detail'] = 'Tamaños distintos (' . (int) $small['tree_size'] . ' y '
            . (int) $large['tree_size'] . '). Sin prueba de consistencia no se puede decir si uno '
            . 'contiene al otro: pídela al log y vuelve a comparar.';

        return $result;
    }

    $consistent = merkleVerifyConsistency(
        (int) $small['tree_size'],
        (int) $large['tree_size'],
        (array) ($consistency['proof'] ?? []),
        (string) $small['root'],
        (string) $large['root'],
    );

    $result['same_view'] = $consistent;
    $result['split_view'] = !$consistent;
    $result['detail'] = $consistent
        ? 'El checkpoint pequeño es prefijo del grande: el log creció sin reescribir nada.'
        : 'El checkpoint de tamaño ' . (int) $small['tree_size'] . ' NO es prefijo del de '
            . (int) $large['tree_size'] . ', y los dos están firmados por el log: historia reescrita '
            . 'o vista dividida.';

    return $result;
}

// ---------------------------------------------------------------------------
// Actos de autoridad (§12.2) e índice por sujeto para pruebas de no inclusión
// (§19.5). Viven aquí y no en otro fichero porque el checkpoint del log firma
// la raíz de los dos árboles a la vez: el append-only y el disperso.
// ---------------------------------------------------------------------------

/**
 * Actos con efectos sobre un nodo. Lista cerrada, y cada uno exige motivo.
 */
if (!defined('AUTHORITY_ACTS')) {
    define('AUTHORITY_ACTS', 'alta,baja,revocacion,bloqueo,degradacion,cuarentena,rechazo_de_identidad');
}

/**
 * Estado del índice por sujeto: clave del árbol disperso => hash de la lista de
 * actos de ese sujeto.
 *
 * @return array<string, string>
 */
function actsSubjects()
{
    $path = logSubjectsPath();

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    if ($text === false) {
        return [];
    }

    $decoded = json_decode($text, true);

    return is_array($decoded) ? $decoded : [];
}

/**
 * @return string Raíz del árbol disperso de actos
 */
function actsRoot()
{
    return smtRoot(actsSubjects());
}

/**
 * @param string $nodeId
 *
 * @return array<int, array> Actos registrados contra ese nodo, en orden
 */
function actsFor($nodeId)
{
    $acts = [];

    foreach (logLeaves() as $leaf) {
        if (($leaf['type'] ?? '') === 'authority_act' && ($leaf['subject'] ?? null) === $nodeId) {
            $acts[] = $leaf;
        }
    }

    return $acts;
}

/**
 * Valor que representa a un sujeto en el árbol disperso: el hash de la lista de
 * hashes de sus actos. Así el valor cambia en cuanto se añade, se quita o se
 * altera uno.
 *
 * @param array<int, array> $acts
 *
 * @return string
 */
function actsValue(array $acts)
{
    $hashes = [];

    foreach ($acts as $act) {
        $hashes[] = logLeafHash($act);
    }

    return hash('sha3-256', 'QSLP1-demo acts' . canonicalJson($hashes));
}

/**
 * Registra un acto de autoridad y devuelve su prueba de inclusión.
 *
 * La §12.2 no admite actos sin motivo ni sin evidencia, y la regla que la
 * acompaña es la que de verdad cambia el comportamiento: **un bloqueo que no
 * aparece en el log es inválido**. Por eso esta función lanza en lugar de
 * devolver un error silencioso: quien no puede registrar el acto, no puede
 * ejecutarlo.
 *
 * @param string $act Uno de AUTHORITY_ACTS
 * @param string $nodeId Nodo afectado
 * @param string $reason Motivo, en lenguaje claro
 * @param string[] $evidence Hashes de lo que justifica el acto; nunca el contenido
 * @param string $author Quién lo ejecuta
 *
 * @return array{leaf: array, seq: int, inclusion: array, acts_root: string}
 */
function authorityAct($act, $nodeId, $reason, array $evidence, $author)
{
    if (!in_array($act, explode(',', AUTHORITY_ACTS), true)) {
        throw new InvalidArgumentException('Acto de autoridad desconocido: ' . $act);
    }

    if (trim((string) $reason) === '') {
        throw new InvalidArgumentException('Un acto de autoridad sin motivo no es registrable (§12.2)');
    }

    if (trim((string) $nodeId) === '') {
        throw new InvalidArgumentException('Un acto de autoridad tiene que nombrar al nodo afectado');
    }

    $published = logAppend('authority_act', [
        'act' => (string) $act,
        'author' => (string) $author,
        'evidence' => array_values(array_map('strval', $evidence)),
        'node_id' => (string) $nodeId,
        'reason' => (string) $reason,
    ], (string) $nodeId);

    // El índice por sujeto se actualiza después de publicar, con la lista ya
    // completa: si se actualizara antes, la raíz hablaría de un acto que aún no
    // consta en el log.
    $subjects = actsSubjects();
    $subjects[smtKey((string) $nodeId)] = actsValue(actsFor((string) $nodeId));
    ksort($subjects);

    logEnsureDir();

    if (@file_put_contents(logSubjectsPath(), canonicalJson($subjects), LOCK_EX) === false) {
        throw new RuntimeException('No se puede escribir el índice de sujetos: ' . logSubjectsPath());
    }

    return $published + ['acts_root' => actsRoot()];
}

/**
 * Prueba de que un nodo tiene —o no tiene— actos de autoridad en su contra.
 *
 * Con un sujeto sin actos, esto es una **prueba de no ocurrencia** (§19.5): el
 * nodo central acusado de censura demuestra que no bloqueó a nadie, y el nodo
 * ligero demuestra que nunca recibió una orden. La prueba vale contra la
 * `acts_root` que el log firmó en su checkpoint, no contra lo que diga el nodo.
 *
 * @param string $nodeId
 *
 * @return array<string, mixed>
 */
function actsProofFor($nodeId)
{
    $subjects = actsSubjects();
    $key = smtKey((string) $nodeId);
    $acts = actsFor((string) $nodeId);

    return [
        'node_id' => (string) $nodeId,
        'acts' => $acts,
        'acts_count' => count($acts),
        'proof' => smtProof($key, $subjects),
        'checkpoint' => logLastCheckpoint(),
        'means' => empty($acts)
            ? 'Prueba de NO inclusión: no existe ningún acto de autoridad contra este nodo en la '
                . 'vista del log que cubre este checkpoint.'
            : 'Prueba de inclusión: estos son todos los actos contra este nodo, y no hay más en '
                . 'esta vista del log.',
    ];
}

/**
 * Comprueba una prueba de actos: que el valor del sujeto se corresponda con los
 * actos que se enseñan y que el camino cuelgue de la raíz firmada.
 *
 * @param array $proof Lo que devuelve actsProofFor()
 * @param string $actsRootHex Raíz firmada por el log
 *
 * @return bool
 */
function actsVerify($proof, $actsRootHex)
{
    if (!is_array($proof) || !isset($proof['proof'])) {
        return false;
    }

    $acts = (array) ($proof['acts'] ?? []);
    $expected = empty($acts) ? null : actsValue($acts);
    $value = $proof['proof']['value'] ?? null;

    if ($expected === null) {
        // Se afirma que no hay actos: la hoja tiene que estar vacía.
        if ($value !== null) {
            return false;
        }
    } elseif (!is_string($value) || !hash_equals($expected, strtolower($value))) {
        // Se enseñan actos: el valor del árbol tiene que ser exactamente el de
        // esa lista, ni uno más ni uno menos.
        return false;
    }

    return smtVerify($proof['proof'], $actsRootHex);
}

// ---------------------------------------------------------------------------
// Identidades publicadas (§12.1). Mientras no haya CA, el log de certificados
// es un log de identidades: el efecto que importa es el mismo, que nadie pueda
// presentar en el handshake una identidad que no consta públicamente.
// ---------------------------------------------------------------------------

/**
 * Clave pública del log, tal como la conoce quien verifica.
 *
 * Se lee de disco y no se pide al log, a propósito: una clave que entrega el
 * propio log no demuestra de quién es. Así funciona Certificate Transparency,
 * donde las claves de los logs vienen preinstaladas en el cliente; aquí los
 * tres roles comparten máquina, así que «preinstalada» quiere decir este
 * fichero. En un despliegue de verdad llega por otra vía y se fija.
 *
 * @return string|null Clave pública ML-DSA cruda, o null si no hay log todavía
 */
function logPublicKey()
{
    $path = IDENTITY_DIR . '/log.pub';

    if (!is_file($path)) {
        return null;
    }

    $raw = base64_decode(trim((string) file_get_contents($path)), true);

    return $raw === false ? null : $raw;
}

/**
 * Busca la hoja que publica una clave pública concreta.
 *
 * @param string $publicKeyRaw
 *
 * @return array|null La hoja, o null si esa identidad no consta
 */
function findPublishedIdentity($publicKeyRaw)
{
    $encoded = b64uEncode($publicKeyRaw);

    foreach (logLeaves() as $leaf) {
        if (($leaf['type'] ?? '') === 'identity' && ($leaf['body']['public_key'] ?? null) === $encoded) {
            return $leaf;
        }
    }

    return null;
}

/**
 * Publica la identidad de un rol si no constaba, y devuelve su prueba de
 * inclusión recién hecha.
 *
 * La prueba se genera en el momento porque depende del tamaño del árbol: el log
 * crece, y una prueba vieja pliega hasta una raíz que ya no es la última. Lo
 * que la ata es la firma del log sobre la raíz y el tamaño que esa prueba usa.
 *
 * @param string $side "app", "srv" o "log"
 *
 * @return array{leaf: array, inclusion: array}
 */
function publishIdentity($side)
{
    $identity = loadOrCreateIdentity($side);
    $leaf = findPublishedIdentity($identity['public']);

    if ($leaf === null) {
        $published = logAppend('identity', [
            'fingerprint' => identityFingerprint($identity['public']),
            'node_id' => nodeId($identity['public']),
            'public_key' => b64uEncode($identity['public']),
            'role' => (string) $side,
            'sig_alg' => SIG_ALG,
        ], nodeId($identity['public']));

        return ['leaf' => $published['leaf'], 'inclusion' => $published['inclusion']];
    }

    return ['leaf' => $leaf, 'inclusion' => logInclusionProof((int) $leaf['seq'])];
}

/**
 * Comprueba que una identidad consta en el log (§12.1).
 *
 * El handshake rechaza lo que no pase por aquí. Sin esta comprobación, una
 * autoridad puede emitir en secreto una identidad para suplantar a un nodo y
 * nadie se enteraría; con ella, para suplantar hay que dejarlo escrito.
 *
 * @param string $publicKeyRaw Identidad que se afirma
 * @param array|null $published Lo que devolvió publishIdentity() en el otro extremo
 * @param string $logPublicKey Clave pública del log, conocida por otra vía
 *
 * @return array{ok: bool, detail: string}
 */
function verifyPublishedIdentity($publicKeyRaw, $published, $logPublicKey)
{
    if (!is_array($published) || !isset($published['leaf'], $published['inclusion'])) {
        return ['ok' => false, 'detail' => 'No viene la prueba de que esa identidad consta en el log'];
    }

    $leaf = $published['leaf'];

    if (!is_array($leaf) || ($leaf['type'] ?? '') !== 'identity') {
        return ['ok' => false, 'detail' => 'La hoja aportada no publica una identidad'];
    }

    if (($leaf['body']['public_key'] ?? null) !== b64uEncode($publicKeyRaw)) {
        return ['ok' => false, 'detail' => 'La hoja del log publica otra clave distinta de la ofrecida'];
    }

    if (!hash_equals(logLeafHash($leaf), strtolower((string) $published['inclusion']['leaf_hash']))) {
        return ['ok' => false, 'detail' => 'El hash de la prueba no es el de la hoja aportada'];
    }

    if (!logVerifyInclusion($published['inclusion'], $logPublicKey, $leaf)) {
        return ['ok' => false, 'detail' => 'La prueba de inclusión no verifica contra la clave del log'];
    }

    return ['ok' => true, 'detail' => 'La identidad consta en el log, en la entrada nº '
        . (int) $published['inclusion']['seq'] . ' de ' . (int) $published['inclusion']['tree_size']];
}
