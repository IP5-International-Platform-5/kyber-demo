<?php

// Include CORS headers, the ephemeral store and the signing identity
require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

require_once __DIR__ . '/../libs/kyber_utils.php';
require_once __DIR__ . '/../libs/identity.php';
// nodeId(): el identificador autocertificante que los dos extremos ponen dentro de receipt_core.
require_once __DIR__ . '/../libs/canonical.php';
// El log: para exigir que la identidad del cliente conste publicada (§12.1) y
// para registrar el rechazo si hay que rechazar (§12.2).
require_once __DIR__ . '/../libs/transparency.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    response(json_encode([
        'error' => 'Method not allowed. Use POST.',
    ]));
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);

foreach (['ciphertext', 'key_id', 'identity', 'signature'] as $field) {
    if (!isset($data[$field]) || $data[$field] === '') {
        http_response_code(400);
        response(json_encode([
            'error' => "Incomplete data. The \"$field\" field is required.",
        ]));
        exit;
    }
}

// The ephemeral private key for this exchange, plus the transcript we signed.
// If it is gone, the offer expired or was already answered.
$offer = storeGet('srv', $data['key_id']);

if ($offer === null) {
    http_response_code(409);
    response(json_encode([
        'error' => 'Unknown or expired key_id. Start again from get_public_key.',
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

// La identidad del cliente también tiene que constar en el log (§12.1): la
// exigencia es simétrica, o el nodo con autoridad sería el único al que se le
// pide acreditarse.
$log_key = logPublicKey();

if ($log_key === null) {
    http_response_code(503);
    response(json_encode([
        'error' => 'No se conoce la clave pública del log de transparencia, así que no se puede '
            . 'comprobar que la identidad del cliente esté publicada (§12.1).',
    ]));
    exit;
}

$published_c = verifyPublishedIdentity($identity_c, $data['identity_log'] ?? null, $log_key);

if (!$published_c['ok']) {
    http_response_code(409);
    response(json_encode([
        'error' => 'La identidad del cliente no consta en el log de transparencia. Se rechaza.',
        'detail' => $published_c['detail'],
    ]));
    exit;
}

// Authentication is mutual: the other end proves who it is before we touch the
// ciphertext with our private key (§7.3). Trust on first use, same caveat as
// the other side.
$pinned = IDENTITY_DIR . '/app.pinned';

if (is_file($pinned)) {
    $known = base64_decode(trim(file_get_contents($pinned)), true);

    if (!hash_equals($known, $identity_c)) {
        // Rechazar a un nodo es un acto con efectos sobre él, y la §12.2 no
        // admite actos invisibles: se registra con motivo, evidencia y autor
        // ANTES de ejecutarlo. La regla que la acompaña es dura y aquí está
        // implementada tal cual: un bloqueo que no aparece en el log es
        // inválido, así que si no se puede registrar, no se bloquea. No
        // bloquear no significa aceptar: significa que el acto no surte
        // efecto y se dice por qué.
        try {
            $act = authorityAct(
                'rechazo_de_identidad',
                nodeId($identity_c),
                'La identidad ofrecida no coincide con la que este nodo tenía fijada para ese par '
                    . '(trust on first use, §5.3).',
                [
                    'pinned_fingerprint:' . identityFingerprint($known),
                    'offered_fingerprint:' . identityFingerprint($identity_c),
                    'key_id_hash:' . hash('sha3-256', (string) $data['key_id']),
                ],
                nodeId(loadOrCreateIdentity('srv')['public']),
            );
        } catch (Throwable $e) {
            http_response_code(503);
            error_log('set_shared_secret: no se pudo registrar el rechazo: ' . $e->getMessage());
            response(json_encode([
                'error' => 'No se puede registrar el rechazo en el log de transparencia, así que el '
                    . 'rechazo no se ejecuta: un acto de autoridad que no consta es inválido (§12.2). '
                    . 'Vuelve a intentarlo cuando el log esté disponible.',
            ]));
            exit;
        }

        http_response_code(409);
        response(json_encode([
            'error' => 'The client identity changed since it was pinned. Refusing the exchange.',
            'pinned_fingerprint' => identityFingerprint($known),
            'offered_fingerprint' => identityFingerprint($identity_c),
            // Quien reciba este rechazo puede comprobarlo y, sobre todo,
            // cualquiera puede ver después que ocurrió.
            'authority_act' => [
                'seq' => $act['seq'],
                'acts_root' => $act['acts_root'],
                'inclusion' => $act['inclusion'],
            ],
        ]));
        exit;
    }
}

// Chains to the transcript we signed in the previous step, so this answer
// cannot be lifted out of another handshake.
$th2 = transcript2($offer['th1'], $ciphertext, $identity_c);

if (!verifyTranscript($identity_c, $th2, $signature_c)) {
    http_response_code(409);
    response(json_encode([
        'error' => 'The client signature does not cover this answer.',
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

    // One decapsulation per key pair. The private key dies here.
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
        // Proof that this side derived the same keys from the same transcript.
        // QSLP/1 sends it as FINISHED (§7.5).
        'confirmation' => confirmationTag($result['shared_secret'], $th2),
        'client_identity_fingerprint' => identityFingerprint($identity_c),
        'identity_fingerprint' => $fingerprint_s,
        'client_signature_verified' => true,
        'client_node_id' => nodeId($identity_c),
        'client_identity_in_log' => $published_c['detail'],
    ]));
} catch (Exception $e) {
    http_response_code(500);
    error_log('set_shared_secret: ' . $e->getMessage());
    response(json_encode(['error' => 'Internal server error']));
}

function response($body)
{
    log_response($body);
    echo $body;
}
