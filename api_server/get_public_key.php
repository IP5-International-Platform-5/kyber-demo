<?php
// Debug (uncomment to trace in the PHP error log)
//error_log("get_public_key.php running");

# Include CORS headers and path constants
require_once __DIR__ . '/../api/cors_headers.php';
require_once __DIR__ . '/config.php';

# Public key endpoint (JSON)
header('Content-Type: application/json');

require_once __DIR__ . '/../api/kyber_utils.php';

# Only GET allowed
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use GET.'
    ]));
    exit;
}

# Obtain the public key
$result = getPublicKey(PUBLIC_KEY_PATH);
//error_log('getPublicKey() result: ' . print_r($result, true));

# If missing, generate a new Kyber key pair and read the public key again
if (isset($result['error'])) {
    error_log("No public key found; generating new key pair");
    $generate_result = generateKyberKeypair(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);

    if (!isset($generate_result['error'])) {
        error_log("Key pair generated; reading public key");
        $result = getPublicKey(PUBLIC_KEY_PATH);
    } else {
        # Return generation error to the client
        $result = $generate_result;
    }
}

$response = json_encode($result);

response($response);

function response($body) {
    log_request("RESPONSE: {$body}");
    echo $body;
}
