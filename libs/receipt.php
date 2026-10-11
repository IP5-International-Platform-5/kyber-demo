<?php

/**
 * Firma por mensaje y acuse de recibo firmado (§11.1, §11.2).
 *
 * Ésta es la parte que separa QSLP/1 de "un canal cifrado". AES-GCM autentica
 * al emisor *ante el receptor*, porque los dos tienen la misma clave; no
 * prueba nada ante un tercero, que no puede saber cuál de los dos calculó el
 * tag. El no repudio exige firma asimétrica, y la exige en los dos sentidos:
 *
 * - El emisor firma receipt_core, y así el receptor puede probar la autoría.
 * - El receptor firma de vuelta, y así el emisor puede probar la entrega y la
 *   aceptación.
 *
 * La segunda mitad es la que casi todos los diseños se saltan, y es la que
 * protege al nodo débil frente a la autoridad fuerte: sin ella, el nodo central
 * siempre puede sostener que no llegó nada.
 *
 * receipt_core nombra a emisor, receptor, sid y th a propósito (§11.1). Una
 * firma que solo cubre el contenido la puede reenviar su receptor a un tercero
 * como si hubiera estado dirigida a él: es el *surreptitious forwarding*.
 * Nombrar los dos extremos y el handshake hace que esa falsificación falle.
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/identity.php';

if (!defined('RECEIPT_DOMAIN')) {
    define('RECEIPT_DOMAIN', 'QSLP1-demo RC');
}

if (!defined('RECEIPT_ACK_DOMAIN')) {
    define('RECEIPT_ACK_DOMAIN', 'QSLP1-demo RCPT');
}

// Los registros de recibo viven junto al diario: los dos son hashes y firmas, y
// ninguno puede contener texto en claro ni material de clave (§15.2).
if (!defined('RECEIPT_DIR')) {
    define('RECEIPT_DIR', __DIR__ . '/../journal/receipts');
}

/**
 * Construye receipt_core. Los nombres de campo y su contenido siguen la §11.1
 * al pie de la letra; los hashes van en hexadecimal minúscula y las claves y
 * firmas en base64url (§6.1).
 *
 * @param string $sid Identificador de sesión que derivaron los dos extremos
 * @param int $seq Número de secuencia del registro dentro de la sesión
 * @param string $from Identificador del nodo emisor (§5.1)
 * @param string $to Identificador del nodo receptor
 * @param string $ts RFC 3339 en UTC
 * @param string $payloadHashHex SHA3-256 del texto en claro
 * @param string $thHex Hash del transcript del handshake al que pertenece el mensaje
 *
 * @return array<string, mixed>
 */
function receiptCore($sid, $seq, $from, $to, $ts, $payloadHashHex, $thHex)
{
    return [
        'sid' => (string) $sid,
        'seq' => (int) $seq,
        'from' => (string) $from,
        'to' => (string) $to,
        'ts' => (string) $ts,
        'payload_hash' => strtolower((string) $payloadHashHex),
        'th' => strtolower((string) $thHex),
    ];
}

/**
 * @param array $core
 *
 * @return string SHA3-256 de la serialización canónica, 64 caracteres hexadecimales
 */
function receiptCoreHash(array $core)
{
    return hash('sha3-256', canonicalJson($core));
}

/**
 * @param array $core
 *
 * @return bool Si la estructura tiene todos los campos que exige la §11.1, con
 *              la forma esperada. Un campo que falta es una puerta a la falsificación.
 */
function receiptCoreWellFormed($core)
{
    if (!is_array($core)) {
        return false;
    }

    $expected = ['sid', 'seq', 'from', 'to', 'ts', 'payload_hash', 'th'];

    if (array_diff($expected, array_keys($core)) !== [] || array_diff(array_keys($core), $expected) !== []) {
        // También se rechazan los campos de más: lo que no entendemos es algo
        // que la firma cubre y nuestras comprobaciones no.
        return false;
    }

    return is_string($core['sid'])
        && is_int($core['seq']) && $core['seq'] >= 0
        && is_string($core['from']) && is_string($core['to'])
        && is_string($core['ts'])
        && preg_match('/^[0-9a-f]{64}$/', (string) $core['payload_hash']) === 1
        && preg_match('/^[0-9a-f]{64}$/', (string) $core['th']) === 1;
}

/**
 * @param string $privateKey Clave privada ML-DSA cruda del emisor
 * @param array $core
 *
 * @return string Firma en base64url
 */
function signReceiptCore($privateKey, array $core)
{
    return b64uEncode(signDomain($privateKey, RECEIPT_DOMAIN, canonicalJson($core)));
}

/**
 * @param string $publicKey Clave pública ML-DSA cruda del emisor que se afirma
 * @param array $core
 * @param string $signatureB64u
 *
 * @return bool
 */
function verifyReceiptCore($publicKey, array $core, $signatureB64u)
{
    $signature = b64uDecode((string) $signatureB64u);

    if ($signature === false) {
        return false;
    }

    return verifyDomain($publicKey, RECEIPT_DOMAIN, canonicalJson($core), $signature);
}

/**
 * Acuse de recibo firmado (§11.2).
 *
 * La §11.2 pide una firma sobre SHA3-256(receipt_core). Ésta cubre además quién
 * acusó y cuándo, que es estrictamente más: la firma de un hash a secas no dice
 * *quién* aceptó el mensaje, y eso es la mitad de lo que el emisor necesita
 * poder demostrar.
 *
 * @param string $privateKey Clave privada ML-DSA cruda del receptor
 * @param string $rcHashHex
 * @param string $byNodeId Identificador del nodo receptor
 *
 * @return array<string, mixed>
 */
function buildReceipt($privateKey, $rcHashHex, $byNodeId)
{
    $body = [
        'by' => (string) $byNodeId,
        'rc_hash' => strtolower((string) $rcHashHex),
        'ts' => rfc3339(),
    ];

    return [
        'qslp' => 1,
        'type' => 'RECEIPT',
    ] + $body + [
        'sig_alg' => SIG_ALG,
        'signature' => b64uEncode(signDomain($privateKey, RECEIPT_ACK_DOMAIN, canonicalJson($body))),
    ];
}

/**
 * @param array $receipt
 * @param string $publicKey Clave pública ML-DSA cruda del nodo que acusa
 * @param string|null $expectedRcHashHex Hash del que el acuse tiene que hablar
 *
 * @return bool
 */
function verifyReceipt($receipt, $publicKey, $expectedRcHashHex = null)
{
    if (!is_array($receipt)) {
        return false;
    }

    foreach (['by', 'rc_hash', 'ts', 'signature'] as $field) {
        if (!isset($receipt[$field]) || !is_string($receipt[$field])) {
            return false;
        }
    }

    if ($expectedRcHashHex !== null && !hash_equals(strtolower($expectedRcHashHex), strtolower($receipt['rc_hash']))) {
        return false;
    }

    $signature = b64uDecode($receipt['signature']);

    if ($signature === false) {
        return false;
    }

    $body = [
        'by' => $receipt['by'],
        'rc_hash' => strtolower($receipt['rc_hash']),
        'ts' => $receipt['ts'],
    ];

    return verifyDomain($publicKey, RECEIPT_ACK_DOMAIN, canonicalJson($body), $signature);
}

/**
 * Envuelve mensaje y firma en lo que de verdad se cifra.
 *
 * Firmar y después cifrar (§11.1): la firma va *dentro* del AEAD para que quien
 * observa la red no pueda saber quién habla con quién. Firmar por fuera
 * publicaría la identidad del emisor a cualquiera que mire el cable.
 *
 * El mensaje viaja en base64url para que una secuencia de bytes que no sea
 * UTF-8 válido no pueda romper la serialización canónica del sobre.
 *
 * @param string $message Texto en claro
 * @param array $core
 * @param string $privateKey Clave privada ML-DSA cruda del emisor
 *
 * @return array{envelope: string, core_hash: string, signature: string}
 */
function buildMessageEnvelope($message, array $core, $privateKey)
{
    $signature = signReceiptCore($privateKey, $core);

    $envelope = [
        'qslp' => 1,
        'type' => 'MSG',
        'core' => $core,
        'm' => b64uEncode($message),
        'sig' => $signature,
        'sig_alg' => SIG_ALG,
    ];

    return [
        'envelope' => canonicalJson($envelope),
        'core_hash' => receiptCoreHash($core),
        'signature' => $signature,
    ];
}

/**
 * @param string $json Sobre ya descifrado
 *
 * @throws RuntimeException Si el sobre no es uno que podamos comprobar
 *
 * @return array{core: array, message: string, signature: string}
 */
function openMessageEnvelope($json)
{
    $envelope = json_decode((string) $json, true);

    if (!is_array($envelope) || ($envelope['type'] ?? null) !== 'MSG') {
        throw new RuntimeException('El contenido descifrado no es un sobre de mensaje QSLP/1');
    }

    if (!isset($envelope['core'], $envelope['m'], $envelope['sig'])) {
        throw new RuntimeException('Al sobre le falta el núcleo, el contenido o la firma');
    }

    if (!receiptCoreWellFormed($envelope['core'])) {
        throw new RuntimeException('El receipt_core del sobre está mal formado');
    }

    $message = b64uDecode((string) $envelope['m']);

    if ($message === false) {
        throw new RuntimeException('El contenido no es base64url válido');
    }

    return [
        'core' => $envelope['core'],
        'message' => $message,
        'signature' => (string) $envelope['sig'],
    ];
}

/**
 * Ventana deslizante anti-replay de 64 posiciones (§8.2).
 *
 * Sin ella, el no repudio se convierte en un arma: una orden legítimamente
 * firmada se puede reenviar mientras la firma valga, y cada copia verifica.
 *
 * @param array{high?: int, seen?: int[]} $window Estado que viaja con la sesión
 * @param int $seq
 *
 * @return array{ok: bool, window: array, error: string|null}
 */
function replayAccept($window, $seq)
{
    $high = isset($window['high']) ? (int) $window['high'] : -1;
    $seen = isset($window['seen']) && is_array($window['seen']) ? $window['seen'] : [];
    $seq = (int) $seq;

    if ($seq < 0) {
        return ['ok' => false, 'window' => ['high' => $high, 'seen' => $seen], 'error' => 'E_REPLAY'];
    }

    if ($high >= 0 && $seq <= $high - 64) {
        // Demasiado viejo para distinguir un reenvío de una primera vez.
        // Rechazarlo es la única respuesta segura: aceptarlo reabriría la ventana.
        return ['ok' => false, 'window' => ['high' => $high, 'seen' => $seen], 'error' => 'E_REPLAY'];
    }

    if (in_array($seq, $seen, true)) {
        return ['ok' => false, 'window' => ['high' => $high, 'seen' => $seen], 'error' => 'E_REPLAY'];
    }

    $high = max($high, $seq);
    $seen[] = $seq;

    $floor = $high - 64;
    $seen = array_values(array_filter($seen, function ($value) use ($floor) {
        return $value > $floor;
    }));

    return ['ok' => true, 'window' => ['high' => $high, 'seen' => $seen], 'error' => null];
}

/**
 * Cada rol guarda su propia copia: el registro del emisor y el del receptor son
 * evidencias distintas, y una no debe sobrescribir la otra.
 *
 * Se valida contra un par fijo de nombres para que por este parámetro no se
 * pueda salir del directorio de recibos.
 *
 * @param string $side
 *
 * @return string
 */
function receiptRecordDir($side)
{
    if ($side !== 'app' && $side !== 'srv') {
        throw new InvalidArgumentException('El lado del recibo tiene que ser "app" o "srv"');
    }

    return RECEIPT_DIR . '/' . $side;
}

/**
 * Guarda todo lo necesario para construir después un paquete de evidencia (§19.3).
 *
 * Solo hashes, identificadores y firmas. El texto en claro no se guarda a
 * propósito: payload_hash ata la afirmación a él, y quien quiera probar el
 * contenido aporta el texto en el momento de exportar (la §19.3 admite su
 * ausencia justificada).
 *
 * @param string $side Qué rol conserva esta copia ("app" o "srv")
 * @param array $record
 *
 * @return string Ruta escrita
 */
function receiptRecordStore($side, array $record)
{
    if (!isset($record['core_hash']) || preg_match('/^[0-9a-f]{64}$/', (string) $record['core_hash']) !== 1) {
        throw new InvalidArgumentException('Un registro de recibo necesita su core_hash');
    }

    $dir = receiptRecordDir($side);

    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        throw new RuntimeException('No se puede crear el directorio de recibos: ' . $dir);
    }

    $path = $dir . '/' . $record['core_hash'] . '.json';

    if (@file_put_contents($path, canonicalJson($record), LOCK_EX) === false) {
        throw new RuntimeException('No se puede escribir el registro de recibo: ' . $path);
    }

    return $path;
}

/**
 * @param string $side
 * @param string $rcHashHex
 *
 * @return array|null
 */
function receiptRecordLoad($side, $rcHashHex)
{
    if (preg_match('/^[0-9a-f]{64}$/', (string) $rcHashHex) !== 1) {
        return null;
    }

    $path = receiptRecordDir($side) . '/' . $rcHashHex . '.json';

    if (!is_file($path)) {
        return null;
    }

    $text = @file_get_contents($path);

    if ($text === false) {
        return null;
    }

    $record = json_decode($text, true);

    return is_array($record) ? $record : null;
}
