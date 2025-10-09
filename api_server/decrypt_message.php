<?php
# Incluir cabeceras CORS
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Endpoint para descifrar mensajes usando la clave compartida
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

# Método solo permitido: POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Método no permitido. Use POST.'
    ]));
    exit;
}

# Obtener el cuerpo JSON de la petición
$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

# Verificar que se recibieron los datos necesarios
if (!isset($data['encrypted_data']) || empty($data['encrypted_data']) ||
    !isset($data['iv']) || empty($data['iv']) ||
    !isset($data['tag']) || empty($data['tag'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Datos incompletos. Se requieren los campos "encrypted_data", "iv" y "tag".'
    ]));
    exit;
}

# Descifrar el mensaje
$result = decryptMessage($data, SHARED_SECRET_PATH);
$response = json_encode($result);

response($response);

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}