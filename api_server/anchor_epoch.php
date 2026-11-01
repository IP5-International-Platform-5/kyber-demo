<?php

// Cabeceras CORS y almacén efímero
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Cierra las épocas que han terminado y ancla sus raíces de Merkle (§11.4).
//
// Un despliegue real hace esto con un temporizador de 60 s. Este demostrador no
// tiene planificador, así que el endpoint existe para hacerlo a demanda, y
// `force` cierra además la época en curso: es una comodidad para la
// demostración, no comportamiento del protocolo, porque cerrar antes de tiempo
// solo significa un árbol más pequeño.
//
// Sin autorización: la §13 (capacidades) no está implementada aquí, y esto
// responde hashes y firmas a quien lo pida. Queda escrito entre lo que falta en
// el README, en vez de dejarlo para que alguien lo descubra.
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/epoch.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode(['error' => 'Método no permitido. Usa POST.']));
    exit;
}

$data = json_decode((string) file_get_contents('php://input'), true);
$force = is_array($data) && !empty($data['force']);

try {
    $closed = $force ? epochCloseAll() : epochClosePending();
} catch (Throwable $e) {
    http_response_code(500);
    error_log('anchor_epoch: ' . $e->getMessage());
    response(json_encode(['error' => 'No se pudo anclar: ' . $e->getMessage()]));
    exit;
}

$epochs = [];

foreach ($closed as $epoch => $record) {
    // Las hojas se quedan en el registro de la época, en disco; la respuesta
    // lleva la raíz, que es lo único que ancla la §11.4.
    $epochs[] = [
        'epoch' => (int) $epoch,
        'size' => (int) $record['size'],
        'root' => (string) $record['root'],
        'closed_at' => (string) $record['closed_at'],
        'anchor' => $record['anchor'],
        'timestamp_present' => (bool) $record['timestamp']['present'],
        'checkpoint' => $record['checkpoint'],
    ];
}

response(json_encode([
    'anchored' => count($epochs),
    'epochs' => $epochs,
    'epoch_seconds' => EPOCH_SECONDS,
    'current_epoch' => epochOf(),
    'last_checkpoint' => journalLastCheckpoint('srv'),
]));

function response($body)
{
    log_response($body);
    echo $body;
}
