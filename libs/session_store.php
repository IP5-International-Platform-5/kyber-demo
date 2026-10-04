<?php

/**
 * Ephemeral session store, backed by APCu shared memory.
 *
 * Key material must not touch the disk: PHP's own sessions are files, and files
 * outlive the exchange. APCu keeps entries in the shared memory of the php-fpm
 * pool, so they die with the pool and never get backed up by accident.
 *
 * Honest limitation: APCu holds its own copy of whatever we store, and PHP
 * strings are copy-on-write, so wiping our copy does not scrub every byte.
 * Real zeroisation needs the secret to never be a PHP string at all, which the
 * oqsphp binding does not allow today. This is best effort, not a guarantee.
 */

# A session lives five minutes. Long enough to walk through the demo by hand,
# short enough that a forgotten tab stops being a liability.
if (!defined('SESSION_TTL')) {
    define('SESSION_TTL', 300);
}

/**
 * @return bool Whether the store can be used at all.
 */
function storeAvailable() {
    return extension_loaded('apcu') && apcu_enabled();
}

/**
 * Fail loudly rather than silently falling back to disk.
 */
function requireStore() {
    if (!storeAvailable()) {
        throw new RuntimeException(
            'APCu is not available: there is nowhere to keep ephemeral key material. '
            . 'Run inside the project container, which builds the extension.'
        );
    }
}

/**
 * Server-generated opaque handle. Never accept one from the client: a client
 * that picks its own identifier can fix a session or farm entries (QSLP/1 §7.4).
 *
 * @return string 32 hex characters
 */
function newHandle() {
    return bin2hex(random_bytes(16));
}

/**
 * Derive the session identifier. Both ends compute it independently from the
 * shared secret and the transcript, so it is never sent by the client and both
 * sides agree on it without negotiating it. The transcript is TH2, built in
 * identity.php: it covers both nonces, both identities and the signatures.
 *
 * @param string $sharedSecret Raw shared secret
 * @param string $transcriptHash Raw transcript hash
 * @return string 32 hex characters
 */
function deriveSid($sharedSecret, $transcriptHash) {
    $sid = hash_hkdf('sha3-256', $sharedSecret, 16, 'QSLP1 sid' . $transcriptHash);

    return bin2hex($sid);
}

/**
 * @param string $namespace Which side of the demo owns the entry ("app" / "srv")
 * @param string $id Handle or session identifier
 * @param array $data Entry contents
 * @param int $ttl Seconds to live
 * @return bool
 */
function storePut($namespace, $id, array $data, $ttl = SESSION_TTL) {
    requireStore();
    $data['created_at'] = time();

    return apcu_store("kyber:$namespace:$id", $data, $ttl);
}

/**
 * @return array|null Null when the entry is absent or has expired.
 */
function storeGet($namespace, $id) {
    requireStore();
    $ok = false;
    $data = apcu_fetch("kyber:$namespace:$id", $ok);

    return ($ok && is_array($data)) ? $data : null;
}

/**
 * Drop an entry, wiping what we can of it first.
 */
function storeForget($namespace, $id) {
    requireStore();
    $data = storeGet($namespace, $id);
    if (is_array($data)) {
        wipeSecrets($data);
    }
    apcu_delete("kyber:$namespace:$id");
}

/**
 * Overwrite every string in the array in place. See the limitation noted above.
 */
function wipeSecrets(array &$data) {
    foreach ($data as $key => &$value) {
        if (is_string($value) && $value !== '') {
            if (function_exists('sodium_memzero')) {
                sodium_memzero($value);
            } else {
                $value = str_repeat("\0", strlen($value));
            }
        }
    }
    unset($value);
}
