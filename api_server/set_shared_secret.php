<?php

# Include CORS headers, the ephemeral store and the signing identity
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
require_once __DIR__ . '/../libs/identity.php';
// nodeId(): el identificador autocertificante que los dos extremos ponen dentro de receipt_core.
require_once __DIR__ . '/../libs/canonical.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.'
    ]));
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);

foreach (['ciphertext', 'key_id', 'identity', 'signature'] as $field) {
    if (!isset($data[$field]) || $data[$field] === '') {
        http_response_code(400);
        response(json_encode([
            'error' => "Incomplete data. The \"$field\" field is required."
        ]));
        exit;
    }
}

# The ephemeral private key for this exchange, plus the transcript we signed.
# If it is gone, the offer expired or was already answered.
$offer = storeGet('srv', $data['key_id']);

if ($offer === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Unknown or expired key_id. Start again from get_public_key.'
    ]));
    exit;
}

$ciphertext = base64_decode(trim((string) $data['ciphertext']), true);
$identity_c = base64_decode(trim((string) $data['identity']), true);
$signature_c = base64_decode(trim((string) $data['signature']), true);

if ($ciphertext === false || $identity_c === false || $signature_c === false) {
    http_response_code(400);
    response(json_encode(['error' => 'Ciphertext, identity or signature is not valid base64']));
    exit;
}

# Authentication is mutual: the other end proves who it is before we touch the
# ciphertext with our private key (§7.3). Trust on first use, same caveat as
# the other side.
$pinned = IDENTITY_DIR . '/app.pinned';

if (is_file($pinned)) {
    $known = base64_decode(trim(file_get_contents($pinned)), true);

    if (!hash_equals($known, $identity_c)) {
        http_response_code(409);
        response(json_encode([
            'error' => 'The client identity changed since it was pinned. Refusing the exchange.',
            'pinned_fingerprint' => identityFingerprint($known),
            'offered_fingerprint' => identityFingerprint($identity_c),
        ]));
        exit;
    }
}

# Chains to the transcript we signed in the previous step, so this answer
# cannot be lifted out of another handshake.
$th2 = transcript2($offer['th1'], $ciphertext, $identity_c);

if (!verifyTranscript($identity_c, $th2, $signature_c)) {
    http_response_code(409);
    response(json_encode([
        'error' => 'The client signature does not cover this answer.'
    ]));
    exit;
}

if (!is_file($pinned)) {
    @file_put_contents($pinned, base64_encode($identity_c));
}

try {
    $result = decapsulateSharedSecret($data['ciphertext'], $offer['private_key']);

    if (isset($result['error'])) {
        http_response_code(500);
        response(json_encode($result));
        exit;
    }

    $sid = deriveSid($result['shared_secret'], $th2);

    // La identidad del par viaja con la sesión: cada registro que acepte este
    // nodo hay que comprobarlo contra la identidad que completó *este*
    // handshake, y no contra la clave que el mensaje diga (§11.1). La ventana
    // anti-replay vive aquí también, porque es por sesión (§8.2).
    storePut('srv', $sid, [
        'shared_secret' => $result['shared_secret'],
        'th2' => $th2,
        'peer_identity' => $identity_c,
        'replay' => ['high' => -1, 'seen' => []],
    ]);

    # One decapsulation per key pair. The private key dies here.
    storeForget('srv', $data['key_id']);

    try {
        $identity_s = loadOrCreateIdentity('srv');
        $fingerprint_s = identityFingerprint($identity_s['public']);
    } catch (Throwable $e) {
        $fingerprint_s = null;
    }

    response(json_encode([
        'sid' => $sid,
        'secret_fingerprint' => secretFingerprint($result['shared_secret']),
        # Proof that this side derived the same keys from the same transcript.
        # QSLP/1 sends it as FINISHED (§7.5).
        'confirmation' => confirmationTag($result['shared_secret'], $th2),
        'client_identity_fingerprint' => identityFingerprint($identity_c),
        'identity_fingerprint' => $fingerprint_s,
        'client_signature_verified' => true,
        'client_node_id' => nodeId($identity_c),
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
