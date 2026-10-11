<?php

# Include CORS headers and the ephemeral store
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';

# Only GET allowed
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use GET.'
    ]));
    exit;
}

# A fresh key pair per request. There is no stored key to read any more: that is
# what gives forward secrecy, because yesterday's traffic cannot be decrypted
# with a key that no longer exists.
$result = generateEphemeralKeypair();

if (isset($result['error'])) {
    http_response_code(500);
    response(json_encode($result));
    exit;
}

# The private key stays on this side, indexed by a handle WE choose. The client
# never picks an identifier (QSLP/1 §7.4), and the handle is good for exactly
# one decapsulation.
$key_id = newHandle();

storePut('srv', $key_id, [
    'private_key' => $result['private_key'],
    'public_key' => $result['public_key'],
]);

response(json_encode([
    'key_id' => $key_id,
    'public_key' => base64_encode($result['public_key']),
    'public_key_length' => $result['public_key_length'],
]));

function response($body) {
    log_response($body);
    echo $body;
}
