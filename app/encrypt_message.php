<?php
# Include CORS headers and path constants
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Encrypt plaintext with AES-GCM using the shared secret (user app backend)
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

# Only POST allowed
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

if (!isset($data['message']) || $data['message'] === '') {
    http_response_code(400);
    response(json_encode([
        'error' => 'Incomplete data. The "message" field is required.'
    ]));
    exit;
}

# Uses shared_secret.key under app/keys/
$result = encryptMessage($data['message'], SHARED_SECRET_PATH);

response(json_encode($result));

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}
