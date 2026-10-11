<?php

# Include CORS headers, the ephemeral store and the signing identity
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
require_once __DIR__ . '/../libs/identity.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.'
    ]));
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);

foreach (['public_key', 'key_id', 'client_nonce', 'server_nonce', 'identity', 'signature'] as $field) {
    if (!isset($data[$field]) || $data[$field] === '') {
        http_response_code(400);
        response(json_encode([
            'error' => "Incomplete offer. The \"$field\" field is required."
        ]));
        exit;
    }
}

$public_key = base64_decode(trim((string) $data['public_key']), true);
$nonce_c = base64_decode(trim((string) $data['client_nonce']), true);
$nonce_s = base64_decode(trim((string) $data['server_nonce']), true);
$identity_s = base64_decode(trim((string) $data['identity']), true);
$signature = base64_decode(trim((string) $data['signature']), true);

if ($public_key === false || $nonce_c === false || $nonce_s === false
    || $identity_s === false || $signature === false) {
    http_response_code(400);
    response(json_encode(['error' => 'The offer has fields that are not valid base64']));
    exit;
}

# 1. Is this the party we spoke to before? Trust on first use: the first
#    exchange is unauthenticated and the fingerprint has to be checked out of
#    band. From then on, a changed identity is refused. A real deployment
#    replaces this with certificates and a transparency log (§5.3, §12.1).
$pinned = IDENTITY_DIR . '/srv.pinned';

if (is_file($pinned)) {
    $known = base64_decode(trim(file_get_contents($pinned)), true);

    if (!hash_equals($known, $identity_s)) {
        http_response_code(409);
        response(json_encode([
            'error' => 'The server identity changed since it was pinned. Refusing the exchange.',
            'pinned_fingerprint' => identityFingerprint($known),
            'offered_fingerprint' => identityFingerprint($identity_s),
        ]));
        exit;
    }
}

# 2. Does the signature actually cover this ephemeral key and these nonces?
$th1 = transcript1($nonce_c, $nonce_s, (string) $data['key_id'], $public_key, $identity_s);

if (!verifyTranscript($identity_s, $th1, $signature)) {
    http_response_code(409);
    response(json_encode([
        'error' => 'The signature does not cover this offer. The key may have been substituted in transit.'
    ]));
    exit;
}

if (!is_file($pinned)) {
    @file_put_contents($pinned, base64_encode($identity_s));
}

$result = encapsulateSharedSecret($data['public_key']);

if (isset($result['error'])) {
    http_response_code(500);
    response(json_encode($result));
    exit;
}

try {
    $identity_c = loadOrCreateIdentity('app');
} catch (Throwable $e) {
    http_response_code(500);
    error_log('get_shared_secret: ' . $e->getMessage());
    response(json_encode(['error' => 'This node has no usable signing identity']));
    exit;
}

# 3. Answer under our own identity, chained to the server's offer.
$th2 = transcript2($th1, $result['ciphertext'], $identity_c['public']);
$signature_c = signTranscript($identity_c['private'], $th2);

$sid = deriveSid($result['shared_secret'], $th2);

storePut('app', $sid, [
    'shared_secret' => $result['shared_secret'],
    'th2' => $th2,
]);

response(json_encode([
    'sid' => $sid,
    'key_id' => $data['key_id'],
    'ciphertext' => base64_encode($result['ciphertext']),
    'identity' => base64_encode($identity_c['public']),
    'identity_fingerprint' => identityFingerprint($identity_c['public']),
    'signature' => base64_encode($signature_c),
    'server_identity_fingerprint' => identityFingerprint($identity_s),
    'server_signature_verified' => true,
    'secret_fingerprint' => secretFingerprint($result['shared_secret']),
    'confirmation' => confirmationTag($result['shared_secret'], $th2),
]));

function response($body) {
    log_response($body);
    echo $body;
}
