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

foreach (['ciphertext', 'nonce', 'key_id'] as $field) {
    if (!isset($data[$field]) || empty($data[$field])) {
        http_response_code(400);
        response(json_encode([
            'error' => "Incomplete data. The \"$field\" field is required."
        ]));
        exit;
    }
}

# The ephemeral private key for this exchange. If it is gone, the session
# expired or the handle was already used: both are refusals, not errors.
$offer = storeGet('srv', $data['key_id']);

if ($offer === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Unknown or expired key_id. Start again from get_public_key.'
    ]));
    exit;
}

try {
    $result = decapsulateSharedSecret($data['ciphertext'], $offer['private_key']);

    if (isset($result['error'])) {
        http_response_code(500);
        response(json_encode($result));
        exit;
    }

    $ciphertext = base64_decode(trim((string) $data['ciphertext']), true);
    $nonce = base64_decode(trim((string) $data['nonce']), true);

    if ($ciphertext === false || $nonce === false) {
        http_response_code(400);
        response(json_encode(['error' => 'Ciphertext or nonce is not valid base64']));
        exit;
    }

    # Same derivation as the other end, from the same transcript. Nobody sends
    # the identifier: if the two sides disagree, the next request simply misses.
    $th = transcriptHash($offer['public_key'], $ciphertext, $nonce);
    $sid = deriveSid($result['shared_secret'], $th);

    storePut('srv', $sid, ['shared_secret' => $result['shared_secret']]);

    # One decapsulation per key pair. The private key dies here.
    storeForget('srv', $data['key_id']);

    response(json_encode([
        'sid' => $sid,
        'secret_fingerprint' => secretFingerprint($result['shared_secret']),
    ]));
} catch (Exception $e) {
    http_response_code(500);
    error_log('set_shared_secret: ' . $e->getMessage());
    response(json_encode(['error' => 'Internal server error']));
}

function response($body) {
    log_response($body);
    echo $body;
}
