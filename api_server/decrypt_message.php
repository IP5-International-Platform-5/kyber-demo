<?php
# Include CORS headers and the ephemeral store
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

# Decrypt payload with AES-GCM using the shared secret
header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';

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

if (!isset($data['encrypted_data']) || empty($data['encrypted_data']) ||
    !isset($data['iv']) || empty($data['iv']) ||
    !isset($data['tag']) || empty($data['tag'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Incomplete data. The fields "encrypted_data", "iv", and "tag" are required.'
    ]));
    exit;
}

if (!isset($data['sid']) || empty($data['sid'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'The session identifier ("sid") is required.'
    ]));
    exit;
}

$session = storeGet('srv', $data['sid']);

if ($session === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Unknown or expired session. Start again from get public key.'
    ]));
    exit;
}

$result = decryptMessage($data, $session['shared_secret']);
$response = json_encode($result);

response($response);

function response($body) {
    log_response($body);
    echo $body;
}
