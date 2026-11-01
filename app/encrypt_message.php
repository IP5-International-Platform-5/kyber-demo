<?php

// Cabeceras CORS y almacén efímero
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Cifra el texto en claro con AES-GCM usando el secreto compartido (backend de
// la aplicación de usuario).
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
// Firmar un receipt_core por mensaje es lo que le da al emisor algo que
// enseñar a un tercero: el tag del AEAD solo convence al otro extremo (§11.1).
require_once __DIR__ . '/../libs/receipt.php';
require_once __DIR__ . '/../libs/journal.php';

// Solo se admite POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Método no permitido. Usa POST.',
    ]));
    exit;
}

// Lee el cuerpo JSON de la petición
$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if (!isset($data['message']) || $data['message'] === '') {
    http_response_code(400);
    response(json_encode([
        'error' => 'Datos incompletos: el campo "message" es obligatorio.',
    ]));
    exit;
}

if (!isset($data['sid']) || empty($data['sid'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Falta el identificador de sesión ("sid").',
    ]));
    exit;
}

// El secreto vive en el almacén efímero, bajo el identificador que derivaron
// los dos extremos. Sin sesión no hay secreto: no queda nada en disco a lo que
// recurrir.
$session = storeGet('app', $data['sid']);

if ($session === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Sesión desconocida o caducada. Empieza otra vez por get_public_key.',
    ]));
    exit;
}

if (!isset($session['peer_identity'], $session['th2'])) {
    // Una sesión anterior a los recibos firmados no sirve para firmar uno: no
    // hay identidad del par a la que dirigir el receipt_core.
    http_response_code(409);
    response(json_encode([
        'error' => 'Esta sesión es anterior a los recibos firmados. Haz un handshake nuevo.',
    ]));
    exit;
}

try {
    $identity = loadOrCreateIdentity('app');
} catch (Throwable $e) {
    http_response_code(500);
    error_log('encrypt_message: ' . $e->getMessage());
    response(json_encode(['error' => 'Este nodo no tiene una identidad de firma utilizable']));
    exit;
}

$message = (string) $data['message'];
$seq = isset($session['next_seq']) ? (int) $session['next_seq'] : 0;

// receipt_core nombra emisor, receptor, sid y th. Los cuatro son obligatorios y
// ninguno es decoración: sin ellos, el receptor podría reenviar esta firma a un
// tercero como si el mensaje hubiera sido para él (§11.1).
$core = receiptCore(
    (string) $data['sid'],
    $seq,
    nodeId($identity['public']),
    nodeId($session['peer_identity']),
    rfc3339(),
    hash('sha3-256', $message),
    bin2hex($session['th2']),
);

try {
    $envelope = buildMessageEnvelope($message, $core, $identity['private']);
} catch (Throwable $e) {
    http_response_code(500);
    error_log('encrypt_message: ' . $e->getMessage());
    response(json_encode(['error' => 'No se pudo firmar el mensaje']));
    exit;
}

// Firmar y después cifrar: la firma viaja dentro del AEAD, así que quien
// observa la red averigua el tamaño del tráfico y nada sobre quién habla.
$result = encryptMessage($envelope['envelope'], $session['shared_secret']);

if (isset($result['error'])) {
    http_response_code(500);
    response(json_encode($result));
    exit;
}

$session['next_seq'] = $seq + 1;
storePut('app', $data['sid'], $session);

try {
    // Diario propio, para que este nodo pueda después demostrar lo que envió en
    // lugar de limitarse a alegarlo (§19.2).
    $entry = journalAppend('app', 'message_sent', $envelope['core_hash']);

    receiptRecordStore('app', [
        'core' => $core,
        'core_hash' => $envelope['core_hash'],
        'sender_signature' => $envelope['signature'],
        'sender_identity' => b64uEncode($identity['public']),
        'receiver_identity' => b64uEncode($session['peer_identity']),
        'journal_n' => (int) $entry['n'],
        'journal_entry' => $entry,
        // La época es asunto del receptor: es el nodo que construye el árbol.
        // Este lado rellena el acuse cuando llega.
        'receipt' => null,
    ]);

    journalMaybeCheckpoint('app');
} catch (Throwable $e) {
    // Un mensaje ya cifrado no se puede perder porque falle el diario, pero un
    // envío sin registrar es un agujero en la evidencia y tiene que verse.
    error_log('encrypt_message: falló el diario: ' . $e->getMessage());
    $result['journal_error'] = 'El envío no se pudo anotar en el diario: ' . $e->getMessage();
}

$result['seq'] = $seq;
$result['rc_hash'] = $envelope['core_hash'];
$result['receipt_core'] = $core;

response(json_encode($result));

function response($body)
{
    log_response($body);
    echo $body;
}
