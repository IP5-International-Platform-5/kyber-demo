<?php
# Include CORS headers and path constants
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Kyber encapsulation: create shared secret + ciphertext (user app backend)
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.'
    ]));
    exit;
}

# Read JSON request body
$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if (!isset($data['public_key']) || empty($data['public_key'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'The server public key is required in the JSON body ("public_key").'
    ]));
    exit;
}

$public_key = $data['public_key'];

# Encapsulate against server public key; writes app/keys/shared_secret.key
$result = encapsulateSharedSecret($public_key, SHARED_SECRET_PATH);

response(json_encode($result));

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}
