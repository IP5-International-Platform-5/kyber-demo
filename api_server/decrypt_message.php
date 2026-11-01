<?php

// Cabeceras CORS y almacén efímero
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Descifra el contenido con AES-GCM usando el secreto compartido
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
// Nada se entrega antes de que verifique la firma del emisor, y nada se
// responde sin un acuse de recibo firmado (§11.1, §11.2).
require_once __DIR__ . '/../libs/receipt.php';
require_once __DIR__ . '/../libs/journal.php';
require_once __DIR__ . '/../libs/epoch.php';

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

if (!isset($data['encrypted_data']) || empty($data['encrypted_data']) ||
    !isset($data['iv']) || empty($data['iv']) ||
    !isset($data['tag']) || empty($data['tag'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Datos incompletos: los campos "encrypted_data", "iv" y "tag" son obligatorios.',
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

$session = storeGet('srv', $data['sid']);

if ($session === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Sesión desconocida o caducada. Empieza otra vez por get_public_key.',
    ]));
    exit;
}

if (!isset($session['peer_identity'], $session['th2'])) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Esta sesión es anterior a los recibos firmados. Haz un handshake nuevo.',
    ]));
    exit;
}

$result = decryptMessage($data, $session['shared_secret']);

if (isset($result['error'])) {
    http_response_code(400);
    response(json_encode($result));
    exit;
}

// A partir de aquí el texto en claro existe pero NO se entrega. Todo lo que
// sigue se ejecuta primero, y cualquier fallo devuelve un error en lugar del
// mensaje: una firma que se comprueba después de entregar el contenido no
// protege nada.
try {
    $envelope = openMessageEnvelope($result['message']);
} catch (Throwable $e) {
    http_response_code(400);
    response(json_encode([
        'error' => 'E_FORMAT',
        'detail' => $e->getMessage(),
    ]));
    exit;
}

$core = $envelope['core'];

try {
    $identity = loadOrCreateIdentity('srv');
} catch (Throwable $e) {
    http_response_code(500);
    error_log('decrypt_message: ' . $e->getMessage());
    response(json_encode(['error' => 'Este nodo no tiene una identidad de firma utilizable']));
    exit;
}

$expected = [
    // El identificador de sesión que firmó el emisor tiene que ser el que usó.
    'sid' => (string) $data['sid'],
    // Y el handshake: un registro sacado de otra sesión verifica con la misma
    // clave, pero nombra otro transcript.
    'th' => bin2hex($session['th2']),
    'from' => nodeId($session['peer_identity']),
    // Dirigido a nosotros, y a nadie más. Ésta es la comprobación que derrota
    // el surreptitious forwarding (§11.1).
    'to' => nodeId($identity['public']),
];

foreach ($expected as $field => $value) {
    if (!hash_equals($value, (string) $core[$field])) {
        http_response_code(400);
        response(json_encode([
            'error' => 'E_AUTH',
            'detail' => 'El receipt_core firmado no corresponde a esta sesión: campo «' . $field . '»',
        ]));
        exit;
    }
}

if (!clockSkewAcceptable((string) $core['ts'])) {
    // ±120 s (§6.2). Sin ese límite, un registro firmado sigue siendo
    // reenviable mientras la firma valga.
    http_response_code(400);
    response(json_encode([
        'error' => 'E_CLOCK_SKEW',
        'detail' => 'La marca de tiempo de receipt_core se aparta más de 120 s del reloj de este nodo',
    ]));
    exit;
}

if (!hash_equals((string) $core['payload_hash'], hash('sha3-256', $envelope['message']))) {
    http_response_code(400);
    response(json_encode([
        'error' => 'E_AUTH',
        'detail' => 'El contenido no resume al valor que firmó el emisor',
    ]));
    exit;
}

if (!verifyReceiptCore($session['peer_identity'], $core, $envelope['signature'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'E_AUTH',
        'detail' => 'La firma del emisor sobre receipt_core no verifica',
    ]));
    exit;
}

// Solo ahora, con la firma verificada, se deja que el número de secuencia mueva
// la ventana. Comprobar el replay antes permitiría envenenarla con un mensaje
// sin firmar que llevara un seq muy alto.
$replay = replayAccept(isset($session['replay']) ? $session['replay'] : [], (int) $core['seq']);

if (!$replay['ok']) {
    http_response_code(409);
    response(json_encode([
        'error' => $replay['error'],
        'detail' => 'El número de secuencia ' . (int) $core['seq']
            . ' ya se había visto o queda fuera de la ventana de 64',
    ]));
    exit;
}

$session['replay'] = $replay['window'];
storePut('srv', $data['sid'], $session);

$coreHash = receiptCoreHash($core);
// No epochOf(): si la época en curso se ancló antes de tiempo, este recibo
// pertenece a la siguiente que esté abierta. Un árbol anclado no cambia.
$epoch = epochForReceipt();
$receipt = buildReceipt($identity['private'], $coreHash, nodeId($identity['public']));

try {
    $index = epochAddLeaf($epoch, $coreHash);
    $entry = journalAppend('srv', 'message_received', $coreHash);

    receiptRecordStore('srv', [
        'core' => $core,
        'core_hash' => $coreHash,
        'sender_signature' => $envelope['signature'],
        'sender_identity' => b64uEncode($session['peer_identity']),
        'receiver_identity' => b64uEncode($identity['public']),
        'journal_n' => (int) $entry['n'],
        'journal_entry' => $entry,
        'epoch' => $epoch,
        'leaf_index' => $index,
        'receipt' => $receipt,
    ]);

    journalMaybeCheckpoint('srv');
    // Aquí no hay planificador, así que quien llegue a continuación cierra las
    // épocas que ya han terminado (la §11.4 lo quiere con temporizador de 60 s).
    epochClosePending();
} catch (Throwable $e) {
    // Aceptar un mensaje del que no podemos dar cuenta sería emitir un recibo
    // por algo que no aparece en nuestra propia evidencia. Mejor rechazarlo.
    http_response_code(500);
    error_log('decrypt_message: ' . $e->getMessage());
    response(json_encode([
        'error' => 'E_INTERNAL',
        'detail' => 'El mensaje verificó pero no se pudo registrar, así que no se acepta',
    ]));
    exit;
}

response(json_encode([
    'message' => $envelope['message'],
    'seq' => (int) $core['seq'],
    'rc_hash' => $coreHash,
    'epoch' => $epoch,
    'sender_node_id' => (string) $core['from'],
    'sender_signature_verified' => true,
    // No repudio *de recepción*, no solo de origen: esto es lo que permite al
    // nodo ligero demostrar que su mensaje se entregó y se aceptó (§11.2).
    'receipt' => $receipt,
]));

function response($body)
{
    log_response($body);
    echo $body;
}
