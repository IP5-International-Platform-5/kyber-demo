<?php

# Include CORS headers, the ephemeral store and the signing identity
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
require_once __DIR__ . '/../libs/identity.php';

# POST now, not GET: the client contributes a nonce, and the signature has to
# cover it. A signed offer with no client input can be replayed.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.'
    ]));
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
$nonce_c = isset($data['client_nonce']) ? base64_decode(trim((string) $data['client_nonce']), true) : false;

if ($nonce_c === false || strlen($nonce_c) !== 32) {
    http_response_code(400);
    response(json_encode([
        'error' => 'A 32-byte "client_nonce" in base64 is required.'
    ]));
    exit;
}

$result = generateEphemeralKeypair();

if (isset($result['error'])) {
    http_response_code(500);
    response(json_encode($result));
    exit;
}

try {
    $identity = loadOrCreateIdentity('srv');
} catch (Throwable $e) {
    http_response_code(500);
    error_log('get_public_key: ' . $e->getMessage());
    response(json_encode(['error' => 'The server has no usable signing identity']));
    exit;
}

$key_id = newHandle();
$nonce_s = random_bytes(32);

# This signature is the whole point of the step: it binds the ephemeral key to
# an identity and to both nonces. Without it an attacker swaps the key for
# their own and proxies the exchange, and nothing downstream can tell (§7.2).
$th1 = transcript1($nonce_c, $nonce_s, $key_id, $result['public_key'], $identity['public']);
$signature = signTranscript($identity['private'], $th1);

storePut('srv', $key_id, [
    'private_key' => $result['private_key'],
    'public_key' => $result['public_key'],
    'th1' => $th1,
]);

response(json_encode([
    'key_id' => $key_id,
    'public_key' => base64_encode($result['public_key']),
    'public_key_length' => $result['public_key_length'],
    'server_nonce' => base64_encode($nonce_s),
    'identity' => base64_encode($identity['public']),
    'identity_fingerprint' => identityFingerprint($identity['public']),
    'signature' => base64_encode($signature),
]));

function response($body) {
    log_response($body);
    echo $body;
}
