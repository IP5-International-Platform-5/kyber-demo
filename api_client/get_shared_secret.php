<?php
# Incluir cabeceras CORS
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Endpoint para crear una clave compartida
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

# Solo permitir POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Método no permitido. Use POST.'
    ]));
    exit;
}

# Leer el cuerpo JSON
$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if (!isset($data['public_key']) || empty($data['public_key'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Se requiere la clave pública del servidor en el cuerpo JSON.'
    ]));
    exit;
}

$public_key = $data['public_key'];

# Crear una clave compartida y ciphertext
$result = encapsulateSharedSecret($public_key, SHARED_SECRET_PATH);

response(json_encode($result));

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}