<?php

// Cabeceras CORS y almacén efímero
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Comprueba y archiva el acuse de recibo firmado por el receptor (§11.2).
//
// Un acuse que nadie comprueba es una cadena de texto en un registro.
// Verificarlo aquí es lo que lo convierte en algo que este nodo puede enseñar a
// un tercero: la prueba de que el mensaje se entregó y se aceptó, firmada por
// el nodo que lo aceptó.
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/receipt.php';
require_once __DIR__ . '/../libs/journal.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode(['error' => 'Método no permitido. Usa POST.']));
    exit;
}

$data = json_decode((string) file_get_contents('php://input'), true);

foreach (['sid', 'rc_hash', 'receipt'] as $field) {
    if (!isset($data[$field]) || empty($data[$field])) {
        http_response_code(400);
        response(json_encode(['error' => 'Los campos "sid", "rc_hash" y "receipt" son obligatorios.']));
        exit;
    }
}

$session = storeGet('app', $data['sid']);

if ($session === null || !isset($session['peer_identity'])) {
    http_response_code(409);
    response(json_encode(['error' => 'Sesión desconocida o caducada.']));
    exit;
}

$rcHash = strtolower((string) $data['rc_hash']);
$record = receiptRecordLoad('app', $rcHash);

if ($record === null) {
    // No se archiva un acuse de algo que no consta que hayamos enviado: sería
    // evidencia de un mensaje del que este nodo no puede dar cuenta.
    http_response_code(409);
    response(json_encode([
        'error' => 'Este nodo no tiene constancia de haber enviado ' . $rcHash,
    ]));
    exit;
}

$receipt = $data['receipt'];

if (!verifyReceipt($receipt, $session['peer_identity'], $rcHash)) {
    http_response_code(400);
    response(json_encode([
        'error' => 'E_AUTH',
        'detail' => 'La firma del acuse no verifica contra la identidad del par de esta sesión',
    ]));
    exit;
}

if (!hash_equals(nodeId($session['peer_identity']), (string) $receipt['by'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'E_AUTH',
        'detail' => 'El acuse dice haber sido emitido por un nodo que no es el par de esta sesión',
    ]));
    exit;
}

try {
    $entry = journalAppend('app', 'receipt_verified', $rcHash);
    $record['receipt'] = $receipt;
    $record['receipt_journal_n'] = (int) $entry['n'];
    $record['receipt_journal_entry'] = $entry;
    receiptRecordStore('app', $record);
    journalMaybeCheckpoint('app');
} catch (Throwable $e) {
    http_response_code(500);
    error_log('store_receipt: ' . $e->getMessage());
    response(json_encode(['error' => 'El acuse verificó pero no se pudo archivar']));
    exit;
}

response(json_encode([
    'stored' => true,
    'receipt_verified' => true,
    'by' => (string) $receipt['by'],
    'rc_hash' => $rcHash,
    'journal_n' => (int) $entry['n'],
]));

function response($body)
{
    log_response($body);
    echo $body;
}
