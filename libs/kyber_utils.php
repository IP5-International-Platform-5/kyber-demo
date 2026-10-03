<?php

# Both ends must agree on the KEM, so it is declared once, here, and not at each
# call site. ML-KEM-768 (FIPS 203) is the standard; "Kyber768" and "Kyber1024"
# are pre-standard names liboqs still ships, and they do NOT interoperate with it.
if (!defined('KEM_ALG')) {
	define('KEM_ALG', 'ML-KEM-768');
}
/**
 * Generate an ephemeral key pair. Nothing is written to disk.
 *
 * A key pair that outlives the session is the reason this demo had no forward
 * secrecy: whoever got hold of the stored private key could decrypt every
 * exchange ever recorded. These keys live in memory and are used once.
 *
 * @param string $algorithm KEM algorithm (default KEM_ALG)
 * @return array [public_key => raw, private_key => raw, public_key_length => int] or [error => string]
 */
function generateEphemeralKeypair($algorithm = KEM_ALG) {
	try {
		# Skip OQS_KEM_alg_is_enabled; create the KEM directly (avoids edge-case failures on some builds)
		try {
			$kem = new OQS_KEYENCAPSULATION($algorithm);
		} catch (Exception $e) {
			return [
				'error' => "Failed to initialize algorithm $algorithm: " . $e->getMessage()
			];
		}

		# Generate key pair
		$status = $kem->keypair($public_key, $private_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Failed to generate key pair'
			];
		}

		# Raw material, for the caller to put straight into the session store.
		# It must never reach a file nor a response body.
		return [
			'public_key' => $public_key,
			'private_key' => $private_key,
			'public_key_length' => $kem->length_public_key
		];
	} catch (Exception $e) {
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Fingerprint of a shared secret, for display only.
 *
 * Lets both ends check that they derived the same secret without either of them
 * sending it. Truncated and domain-separated on purpose: it identifies the
 * session, it does not reconstruct the key.
 *
 * @param string $shared_secret Raw shared secret (binary)
 * @return string 16 hex characters, grouped in fours for visual comparison
 */
function secretFingerprint($shared_secret) {
	$digest = hash('sha3-256', 'kyber-demo fingerprint v1' . $shared_secret, true);

	return implode(' ', str_split(bin2hex(substr($digest, 0, 8)), 4));
}

/**
 * Encapsulate a shared secret using the remote public key.
 *
 * @param string $remote_public_key Remote public key (base64)
 * @param string $remote_public_key Remote public key (base64)
 * @return array Operation result: [ciphertext => string, secret_fingerprint => string] or [error => string]
 */
function encapsulateSharedSecret($remote_public_key) {
	try {
		if (empty($remote_public_key)) {
			return [
				'error' => 'No public key was provided for encapsulation'
			];
		}

		# Public key is base64 on the wire (same encoding as file storage)
		$public_key = @base64_decode($remote_public_key);
		if ($public_key === false) {
			return [
				'error' => 'Public key is not valid base64'
			];
		}

		$kem = new OQS_KEYENCAPSULATION(KEM_ALG);

		# Encapsulate: ciphertext + shared secret (binary)
		$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Failed to encapsulate shared secret'
			];
		}

		# The caller stores this in the session; it never reaches a file nor a
		# response body. Only the fingerprint is safe to show.
		return [
			'ciphertext' => $ciphertext,
			'shared_secret' => $shared_secret
		];
	} catch (Exception $e) {
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Decapsulate ciphertext from the client and derive the shared secret.
 *
 * @param string $ciphertext Received ciphertext (base64)
 * @return array Operation result: [message => string] or [error => string]
 */
function decapsulateSharedSecret($ciphertext, $private_key) {
	try {
		if ($private_key === '') {
			return [
				'error' => 'No private key for decapsulation: the session expired or was already used'
			];
		}

		# Ciphertext is base64-encoded bytes from the client
		$binary_ciphertext = base64_decode($ciphertext);
		if ($binary_ciphertext === false) {
			return [
				'error' => 'Invalid ciphertext format'
			];
		}

		$kem = new OQS_KEYENCAPSULATION(KEM_ALG);

		# Decapsulate to the same shared secret the client derived
		$status = $kem->decapsulate($shared_secret, $binary_ciphertext, $private_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Failed to decapsulate shared secret'
			];
		}

		return [
			'shared_secret' => $shared_secret
		];
	} catch (Exception $e) {
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Encrypt a message using the shared secret (AES-256-GCM).
 *
 * @param string $message Plaintext to encrypt
 * @return array Operation result: [encrypted_data => string, iv => string] or [error => string]
 */
function encryptMessage($message, $shared_secret) {
	try {
		if (!is_string($shared_secret) || strlen($shared_secret) !== 32) {
			return [
				'error' => 'No usable shared secret for encryption: the session expired'
			];
		}

		# Require OpenSSL AES-256-GCM
		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM is not available. Available methods: " . implode(', ', openssl_get_cipher_methods()));
			return [
				'error' => 'AES-256-GCM is not available on this server'
			];
		}

		# 12-byte GCM IV (NIST recommendation)
		$iv = openssl_random_pseudo_bytes(12);

		# Auth tag filled by openssl_encrypt (16 bytes)
		$tag = null;

		# Empty AAD; tag length 16 (matches decrypt)
		$encrypted_data = openssl_encrypt(
			$message,
			'aes-256-gcm',
			$shared_secret,
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			'',
			16
		);

		if ($encrypted_data === false) {
			error_log("Encryption failed: " . openssl_error_string());
			return [
				'error' => 'Encryption failed: ' . openssl_error_string()
			];
		}

		return [
			'encrypted_data' => base64_encode($encrypted_data),
			'iv' => base64_encode($iv),
			'tag' => base64_encode($tag)
		];
	} catch (Exception $e) {
		error_log("encryptMessage exception: " . $e->getMessage());
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Decrypt a message using the shared secret.
 *
 * @param array $data Payload with the base64 fields: encrypted_data, iv, tag
 * @param string $shared_secret Raw 32-byte shared secret from the session store
 * @return array Operation result: [message => string] or [error => string]
 */
function decryptMessage($data, $shared_secret) {
	try {
		if (!is_string($shared_secret) || strlen($shared_secret) !== 32) {
			return [
				'error' => 'No usable shared secret for decryption: the session expired'
			];
		}

		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM is not available for decryption");
			return [
				'error' => 'AES-256-GCM is not available on this server'
			];
		}

		# JSON fields are base64; trim whitespace from copy/paste
		$encrypted_data = base64_decode(trim((string) $data['encrypted_data']), true);
		$iv = base64_decode(trim((string) $data['iv']), true);
		$tag = base64_decode(trim((string) $data['tag']), true);

		if ($encrypted_data === false || $iv === false || $tag === false) {
			return [
				'error' => 'Invalid ciphertext payload (bad base64)'
			];
		}

		if (strlen($iv) !== 12 || strlen($tag) !== 16) {
			return [
				'error' => 'IV or tag has wrong length for AES-256-GCM'
			];
		}

		# Clear OpenSSL error queue before decrypt (openssl_decrypt may not push if auth fails)
		while (openssl_error_string() !== false) {
		}
		$decrypted = openssl_decrypt(
			$encrypted_data,
			'aes-256-gcm',
			$shared_secret,
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			''
		);

		if ($decrypted === false) {
			$error = [];
			while (($err = openssl_error_string()) !== false) {
				$error[] = $err;
			}
			$detail = implode('; ', $error);
			if ($detail === '') {
				$detail = 'GCM authentication failed (key or tag mismatch between app and server). Run the flow again from "Get public key", or delete shared_secret.key in app/keys and api_server/keys, then encapsulate and send the ciphertext again.';
			}
			return [
				'error' => 'Decryption failed (wrong key or tampered data): ' . $detail
			];
		}

		return [
			'message' => $decrypted
		];
	} catch (Exception $e) {
		error_log("decryptMessage exception: " . $e->getMessage());
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}
