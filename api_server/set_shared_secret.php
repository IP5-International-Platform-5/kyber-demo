<?php
# Include CORS headers and path constants
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Accept Kyber ciphertext and store derived shared secret
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

# Verify that the ciphertext is present
if (!isset($data['ciphertext']) || empty($data['ciphertext'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'Incomplete data. The "ciphertext" field is required.'
    ]));
    exit;
}

try {
    # Kyber decapsulate using server private key; writes shared_secret.key
    $result = decapsulateSharedSecret($data['ciphertext'], PRIVATE_KEY_PATH, SHARED_SECRET_PATH);

    # If there was an error, return it
    if (isset($result['error'])) {
        http_response_code(500);
        response(json_encode($result));
        exit;
    }

    # Return derived secret as base64 (demo visibility only)
    $json_response = json_encode([
        'shared_secret' => base64_encode($result['shared_secret'])
    ]);

    if ($json_response === false) {
        throw new Exception('Failed to encode JSON response: ' . json_last_error_msg());
    }

    response($json_response);
} catch (Exception $e) {
    http_response_code(500);

    response(json_encode([
        'error' => 'Internal server error: ' . $e->getMessage()
    ]));
}

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}
