<?php

// Cabeceras CORS y almacén efímero
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Exporta un paquete de evidencia autocontenido (§19.3).
//
// Pasa el texto en claro en "payload" y el paquete prueba también el contenido;
// omítelo y prueba la entrega de algo cuyo hash está fijado. Los dos casos
// quedan declarados dentro del paquete, porque quien lo lea no debería tener
// que deducir cuál tiene delante.
//
// Aquí tampoco hay autorización: ver la nota de anchor_epoch.php.
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/evidence.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode(['error' => 'Método no permitido. Usa POST.']));
    exit;
}

$data = json_decode((string) file_get_contents('php://input'), true);

if (!isset($data['rc_hash']) || preg_match('/^[0-9a-f]{64}$/', (string) $data['rc_hash']) !== 1) {
    http_response_code(400);
    response(json_encode(['error' => 'Hace falta un "rc_hash" de 64 caracteres hexadecimales en minúscula.']));
    exit;
}

try {
    $package = buildEvidencePackage(
        (string) $data['rc_hash'],
        isset($data['payload']) ? (string) $data['payload'] : null,
    );
} catch (Throwable $e) {
    http_response_code(404);
    response(json_encode(['error' => $e->getMessage()]));
    exit;
}

// Con sangrado a propósito: este fichero está para que lo lea una persona y se
// le entregue a un perito, no solo para que lo analice un programa.
echo json_encode($package, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
log_response(json_encode(['status' => 'paquete de evidencia exportado', 'rc_hash' => $data['rc_hash']]));

function response($body)
{
    log_response($body);
    echo $body;
}
