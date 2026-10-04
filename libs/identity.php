<?php

/**
 * Long-lived signing identity and handshake transcript.
 *
 * Ephemeral KEM keys stop anyone decrypting yesterday's traffic. They do
 * nothing against someone sitting in the middle *today*: the server's ephemeral
 * public key travels in the clear, so an attacker swaps it for their own and
 * proxies the whole exchange. Signing that key with a long-lived identity is
 * what closes it (QSLP/1 §7.2).
 *
 * Note the deliberate asymmetry with the session store: a signing key is
 * *meant* to outlive the session, so it lives on disk with 0600 (§5.2, §15.4).
 * The shared secret is not, and never touches disk.
 */

if (!defined('SIG_ALG')) {
    define('SIG_ALG', 'ML-DSA-65');
}

if (!defined('IDENTITY_DIR')) {
    define('IDENTITY_DIR', __DIR__ . '/../identities');
}

/**
 * Load this side's identity, creating it on first use.
 *
 * @param string $side "app" or "srv"
 * @return array{public: string, private: string} Raw key material
 */
function loadOrCreateIdentity($side) {
    $pub = IDENTITY_DIR . "/$side.pub";
    $sec = IDENTITY_DIR . "/$side.key";

    if (is_file($pub) && is_file($sec)) {
        return [
            'public' => base64_decode(trim(file_get_contents($pub)), true),
            'private' => base64_decode(trim(file_get_contents($sec)), true),
        ];
    }

    if (!is_dir(IDENTITY_DIR) && !@mkdir(IDENTITY_DIR, 0700, true) && !is_dir(IDENTITY_DIR)) {
        throw new RuntimeException('Cannot create the identity directory');
    }

    $sig = new OQS_SIGNATURE(SIG_ALG);
    $public = '';
    $private = '';

    if ($sig->keypair($public, $private) !== OQS_SUCCESS) {
        throw new RuntimeException('Could not generate the signing identity');
    }

    file_put_contents($pub, base64_encode($public));
    file_put_contents($sec, base64_encode($private));
    # The private half is the whole point of an identity: if a third party can
    # sign in your name there is no non-repudiation, only a claim (§5.2).
    @chmod($sec, 0600);
    @chmod($pub, 0644);

    return ['public' => $public, 'private' => $private];
}

/**
 * Short, readable form of a public identity, for a human to compare.
 *
 * @param string $publicKey Raw ML-DSA public key
 * @return string 16 hex characters in groups of four
 */
function identityFingerprint($publicKey) {
    $digest = hash('sha3-256', 'QSLP1-demo identity' . $publicKey, true);

    return implode(' ', str_split(bin2hex(substr($digest, 0, 8)), 4));
}

/**
 * Length-prefixed concatenation, so that no field can be read as another.
 *
 * QSLP/1 uses JCS over JSON (§6.1); this demo uses explicit lengths instead,
 * which is simpler and has the same property that matters here: one and only
 * one byte string per set of fields.
 */
function bind(array $parts) {
    $out = '';
    foreach ($parts as $part) {
        $out .= pack('N', strlen($part)) . $part;
    }

    return $out;
}

/**
 * TH1 — covers the server's offer. What its signature commits to.
 */
function transcript1($nonceClient, $nonceServer, $keyId, $kemPublicKey, $identityServer) {
    return hash('sha3-256', 'QSLP1-demo TH1' . bind([
        $nonceClient, $nonceServer, $keyId, $kemPublicKey, $identityServer,
    ]), true);
}

/**
 * TH2 — adds the client's answer. Chains to TH1, so a reply cannot be lifted
 * out of one handshake and replayed into another.
 */
function transcript2($th1, $ciphertext, $identityClient) {
    return hash('sha3-256', 'QSLP1-demo TH2' . $th1 . bind([$ciphertext, $identityClient]), true);
}

/**
 * @return string Raw signature
 */
function signTranscript($privateKey, $transcriptHash) {
    $sig = new OQS_SIGNATURE(SIG_ALG);
    $signature = '';

    if ($sig->sign($signature, $transcriptHash, $privateKey) !== OQS_SUCCESS) {
        throw new RuntimeException('Signing failed');
    }

    return $signature;
}

/**
 * @return bool Whether the signature is valid for this transcript and identity.
 */
function verifyTranscript($publicKey, $transcriptHash, $signature) {
    if ($publicKey === '' || $signature === '') {
        return false;
    }

    try {
        $sig = new OQS_SIGNATURE(SIG_ALG);

        return $sig->verify($transcriptHash, $signature, $publicKey) === OQS_SUCCESS;
    } catch (Throwable $e) {
        # A malformed key or signature throws rather than returning a status.
        return false;
    }
}

/**
 * Confirmation tag: proof that this side derived the same keys from the same
 * transcript. QSLP/1 §7.5 sends it as FINISHED.
 */
function confirmationTag($sharedSecret, $th2) {
    $kConf = hash_hkdf('sha3-256', $sharedSecret, 32, 'QSLP1 conf' . $th2);

    return bin2hex(substr(hash_hmac('sha3-256', $th2, $kConf, true), 0, 16));
}
