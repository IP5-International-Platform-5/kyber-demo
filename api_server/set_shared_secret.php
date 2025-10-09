<?php
# Incluir cabeceras CORS
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Endpoint para enviar la clave compartida
header('Content-Type: application/json');

# Habilitar logging de errores
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

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

# Verificar que se recibió el ciphertext
if (!isset($data['ciphertext']) || empty($data['ciphertext'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Datos incompletos. Se requiere el campo "ciphertext".'
    ]));
    exit;
}

try {
    # Obtener la clave compartida
    $result = decapsulateSharedSecret($data['ciphertext'], PRIVATE_KEY_PATH, SHARED_SECRET_PATH);

    # Verificar si hubo error
    if (isset($result['error'])) {
        http_response_code(500);
        response(json_encode($result));
        exit;
    }

    # Devolver el resultado en formato JSON
    $json_response = json_encode([
        'shared_secret' => base64_encode($result['shared_secret'])
    ]);

    if ($json_response === false) {
        throw new Exception('Error al codificar la respuesta JSON: ' . json_last_error_msg());
    }

    response($json_response);
} catch (Exception $e) {
    http_response_code(500);

    response(json_encode([
        'error' => 'Error interno del servidor: ' . $e->getMessage()
    ]));
}

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}