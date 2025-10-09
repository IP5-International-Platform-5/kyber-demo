<?php
# Depuración
//error_log("get_public_key.php está siendo ejecutado!");

# Incluir cabeceras CORS
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Endpoint para obtener la clave pública
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

# Método solo permitido: GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Método no permitido. Use GET.'
    ]));
    exit;
}

# Obtener la clave pública
$result = getPublicKey(PUBLIC_KEY_PATH);
//error_log("Resultado de getPublicKey(): " . print_r($result, true));

# Si hay error, intentamos generar un nuevo par de claves
if (isset($result['error'])) {
    error_log("No se encontró clave pública, generando nuevo par de claves");
    $generate_result = generateKyberKeypair(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);

    # Si la generación tuvo éxito (no hay error), obtenemos la clave pública
    if (!isset($generate_result['error'])) {
        error_log("Par de claves generado correctamente, obteniendo clave pública");
        $result = getPublicKey(PUBLIC_KEY_PATH);
    } else {
        # Si hubo error en la generación, lo devolvemos
        $result = $generate_result;
    }
}

$response = json_encode($result);

response($response);

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}