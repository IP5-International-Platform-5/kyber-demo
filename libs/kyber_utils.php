<?php
/**
 * Generate a Kyber key pair and save it to files.
 *
 * @param string $public_key_path Path to write the public key
 * @param string $private_key_path Path to write the private key
 * @param string $algorithm Kyber algorithm (default "Kyber1024")
 * @return array Operation result: [public_key => string, ...] or [error => string]
 */
function generateKyberKeypair($public_key_path, $private_key_path, $algorithm = "Kyber1024") {
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

		# Save keys to files
		file_put_contents($public_key_path, base64_encode($public_key));
		file_put_contents($private_key_path, base64_encode($private_key));

		return [
			'message' => 'Key pair generated and saved successfully',
			'public_key' => base64_encode($public_key),
			'public_key_length' => $kem->length_public_key
		];
	} catch (Exception $e) {
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Read the previously generated public key.
 *
 * @return array Operation result: [public_key => string] or [error => string]
 */
function getPublicKey($public_key_path) {
	if (!file_exists($public_key_path)) {
		return [
			'error' => 'No public key has been generated'
		];
	}

	$public_key = base64_decode(file_get_contents($public_key_path));

	return [
		'public_key' => base64_encode($public_key)
	];
}

/**
 * Encapsulate a shared secret using the remote public key.
 *
 * @param string $remote_public_key Remote public key (base64)
 * @param string $shared_secret_path Path to save the shared secret
 * @return array Operation result: [ciphertext => string, shared_secret => string] or [error => string]
 */
function encapsulateSharedSecret($remote_public_key, $shared_secret_path) {
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

		$kem = new OQS_KEYENCAPSULATION("Kyber1024");

		# Encapsulate: ciphertext + shared secret (binary)
		$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Failed to encapsulate shared secret'
			];
		}

		# Persist for AES-GCM step
		file_put_contents($shared_secret_path, base64_encode($shared_secret));

		# Return ciphertext and shared secret (demo only)
		return [
			'ciphertext' => base64_encode($ciphertext),
			'shared_secret' => base64_encode($shared_secret)
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
function decapsulateSharedSecret($ciphertext, $private_key_path, $shared_secret_path) {
	try {
		if (!file_exists($private_key_path)) {
			return [
				'error' => 'No private key found for decapsulation'
			];
		}

		# Ciphertext is base64-encoded bytes from the client
		$binary_ciphertext = base64_decode($ciphertext);
		if ($binary_ciphertext === false) {
			return [
				'error' => 'Invalid ciphertext format'
			];
		}

		$private_key = base64_decode(file_get_contents($private_key_path));

		$kem = new OQS_KEYENCAPSULATION("Kyber1024");

		# Decapsulate to the same shared secret the client derived
		$status = $kem->decapsulate($shared_secret, $binary_ciphertext, $private_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Failed to decapsulate shared secret'
			];
		}

		file_put_contents($shared_secret_path, base64_encode($shared_secret));

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
function encryptMessage($message, $shared_secret_path) {
	try {
		if (!file_exists($shared_secret_path)) {
			return [
				'error' => 'No shared secret available for encryption'
			];
		}

		# Require OpenSSL AES-256-GCM
		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM is not available. Available methods: " . implode(', ', openssl_get_cipher_methods()));
			return [
				'error' => 'AES-256-GCM is not available on this server'
			];
		}

		# Shared secret file is base64; trim in case of stray newlines
		$raw = trim(file_get_contents($shared_secret_path));
		$shared_secret = base64_decode($raw, true);
		if ($shared_secret === false || strlen($shared_secret) !== 32) {
			return [
				'error' => 'Invalid or corrupted shared secret (expected 32 bytes after base64 decode)'
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
 * @param string $encrypted_data Ciphertext (base64)
 * @param string $iv Initialization vector (base64)
 * @param string $tag Authentication tag (base64)
 * @return array Operation result: [message => string] or [error => string]
 */
function decryptMessage($data, $shared_secret_path) {
	try {
		if (!file_exists($shared_secret_path)) {
			return [
				'error' => 'No shared secret available for decryption'
			];
		}

		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM is not available for decryption");
			return [
				'error' => 'AES-256-GCM is not available on this server'
			];
		}

		# Same load path as encryptMessage()
		$raw = trim(file_get_contents($shared_secret_path));
		$shared_secret = base64_decode($raw, true);
		if ($shared_secret === false || strlen($shared_secret) !== 32) {
			return [
				'error' => 'Invalid or corrupted shared secret (expected 32 bytes after base64 decode)'
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
