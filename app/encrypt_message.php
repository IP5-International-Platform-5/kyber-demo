<?php
# Include CORS headers and the ephemeral store
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

# Encrypt plaintext with AES-GCM using the shared secret (user app backend)
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

if (!isset($data['message']) || $data['message'] === '') {
    http_response_code(400);
    response(json_encode([
        'error' => 'Incomplete data. The "message" field is required.'
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

# The secret lives in the ephemeral store, under the identifier both ends
# derived. No session, no secret: there is nothing on disk to fall back to.
$session = storeGet('app', $data['sid']);

if ($session === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Unknown or expired session. Start again from get public key.'
    ]));
    exit;
}

$result = encryptMessage($data['message'], $session['shared_secret']);

response(json_encode($result));

function response($body) {
    log_response($body);
    echo $body;
}
