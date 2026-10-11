<?php

# Include CORS headers and the ephemeral store
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.'
    ]));
    exit;
}

$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if (!isset($data['public_key']) || empty($data['public_key'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'The server public key is required in the JSON body ("public_key").'
    ]));
    exit;
}

if (!isset($data['key_id']) || empty($data['key_id'])) {
    http_response_code(400);
    response(json_encode([
        'error' => 'The key_id returned by get_public_key is required.'
    ]));
    exit;
}

$public_key = base64_decode(trim((string) $data['public_key']), true);
if ($public_key === false) {
    http_response_code(400);
    response(json_encode(['error' => 'Public key is not valid base64']));
    exit;
}

$result = encapsulateSharedSecret($data['public_key']);

if (isset($result['error'])) {
    http_response_code(500);
    response(json_encode($result));
    exit;
}

# Our own contribution to the transcript, so the session identifier cannot be
# replayed from an exchange we did not take part in.
$nonce = random_bytes(16);

# Both ends derive the same identifier from the secret and the transcript. It
# travels in the response so the browser can quote it, but neither end takes
# the client's word for it: each recomputes it (QSLP/1 §7.4).
$th = transcriptHash($public_key, $result['ciphertext'], $nonce);
$sid = deriveSid($result['shared_secret'], $th);

storePut('app', $sid, ['shared_secret' => $result['shared_secret']]);

response(json_encode([
    'sid' => $sid,
    'key_id' => $data['key_id'],
    'nonce' => base64_encode($nonce),
    'ciphertext' => base64_encode($result['ciphertext']),
    'secret_fingerprint' => secretFingerprint($result['shared_secret']),
]));

function response($body) {
    log_response($body);
    echo $body;
}
