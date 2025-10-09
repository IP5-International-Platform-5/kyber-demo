<?php
/**
 * Genera un par de claves Kyber y las guarda en archivos
 *
 * @param string $algorithm El algoritmo Kyber a usar (por defecto "Kyber1024")
 * @return array Resultado de la operación: [public_key => string, ...] o [error => string]
 */
function generateKyberKeypair($public_key_path, $private_key_path, $algorithm = "Kyber1024") {
	try {
		# Eliminamos la verificación de OQS_KEM_alg_is_enabled para evitar el error
		# Creamos directamente la instancia KEM

		# Crear instancia de Kyber - usamos try/catch en lugar de la verificación previa
		try {
			$kem = new OQS_KEYENCAPSULATION($algorithm);
		} catch (Exception $e) {
			return [
				'error' => "Error al inicializar el algoritmo $algorithm: " . $e->getMessage()
			];
		}

		# Generar par de claves
		$status = $kem->keypair($public_key, $private_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Error al generar el par de claves'
			];
		}

		# Guardar claves en archivos
		file_put_contents($public_key_path, base64_encode($public_key));
		file_put_contents($private_key_path, base64_encode($private_key));

		return [
			'message' => 'Par de claves generado y guardado correctamente',
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
 * Obtiene la clave pública generada previamente
 *
 * @return array Resultado de la operación: [public_key => string] o [error => string]
 */
function getPublicKey($public_key_path) {
	if (!file_exists($public_key_path)) {
		return [
			'error' => 'No existe una clave pública generada'
		];
	}

	$public_key = base64_decode(file_get_contents($public_key_path));

	return [
		'public_key' => base64_encode($public_key)
	];
}

/**
 * Encapsula una clave compartida usando la clave pública remota
 *
 * @param string $remote_public_key Clave pública remota en hexadecimal
 * @param string $shared_secret_path Ruta donde guardar la clave compartida
 * @return array Resultado de la operación: [ciphertext => string, shared_secret => string] o [error => string]
 */
function encapsulateSharedSecret($remote_public_key, $shared_secret_path) {
	try {
		# Verificar que la clave pública esté proporcionada
		if (empty($remote_public_key)) {
			return [
				'error' => 'No se proporcionó una clave pública para encapsular'
			];
		}

		# Convertir la clave pública de hexadecimal a binario
		$public_key = @base64_decode($remote_public_key);
		if ($public_key === false) {
			return [
				'error' => 'La clave pública no es una cadena hexadecimal válida'
			];
		}

		# Crear instancia de Kyber
		$kem = new OQS_KEYENCAPSULATION("Kyber1024");

		# Encapsular para generar ciphertext y clave compartida
		$status = $kem->encapsulate($ciphertext, $shared_secret, $public_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Error al encapsular la clave compartida'
			];
		}

		# Guardar la clave compartida para uso futuro
		file_put_contents($shared_secret_path, base64_encode($shared_secret));

		# Devolver el ciphertext y la clave compartida (solo para demo)
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
 * Procesa el ciphertext recibido del cliente y extrae la clave compartida
 *
 * @param string $ciphertext Texto cifrado recibido (en formato hex)
 * @return array Resultado de la operación: [message => string] o [error => string]
 */
function decapsulateSharedSecret($ciphertext, $private_key_path, $shared_secret_path) {
	try {
		if (!file_exists($private_key_path)) {
			return [
				'error' => 'No existe una clave privada para descifrar'
			];
		}

		# Convertir el ciphertext de hex a binario
		$binary_ciphertext = base64_decode($ciphertext);
		if ($binary_ciphertext === false) {
			return [
				'error' => 'Formato de ciphertext inválido'
			];
		}

		# Cargar clave privada
		$private_key = base64_decode(file_get_contents($private_key_path));

		# Crear instancia de Kyber
		$kem = new OQS_KEYENCAPSULATION("Kyber1024");

		# Descifrar para obtener la clave compartida
		$status = $kem->decapsulate($shared_secret, $binary_ciphertext, $private_key);

		if ($status !== OQS_SUCCESS) {
			return [
				'error' => 'Error al descifrar la clave compartida'
			];
		}

		# Guardar la clave compartida
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
 * Cifra un mensaje usando la clave compartida
 *
 * @param string $message Mensaje a cifrar
 * @return array Resultado de la operación: [encrypted_data => string, iv => string] o [error => string]
 */
function encryptMessage($message, $shared_secret_path) {
	try {
		if (!file_exists($shared_secret_path)) {
			return [
				'error' => 'No existe una clave compartida para cifrar'
			];
		}

		# Verificar que GCM esté disponible
		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM no está disponible. Métodos disponibles: " . implode(', ', openssl_get_cipher_methods()));
			return [
				'error' => 'El modo de cifrado AES-256-GCM no está disponible en este servidor'
			];
		}

		# Cargar clave compartida
		$shared_secret = base64_decode(file_get_contents($shared_secret_path));

		# Generar vector de inicialización aleatorio de 12 bytes (recomendado para GCM)
		//$iv = openssl_random_pseudo_bytes(12);
		#v = '010101010101'; // Francisco

		# Tag de autenticación (será rellenado por openssl_encrypt)
		$tag = null;

		# Cifrar usando AES-256-GCM con la clave compartida
		$encrypted_data = openssl_encrypt(
			$message,
			'aes-256-gcm',
			$shared_secret,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		if ($encrypted_data === false) {
			error_log("Error al cifrar: " . openssl_error_string());
			return [
				'error' => 'Error al cifrar: ' . openssl_error_string()
			];
		}

		return [
			'encrypted_data' => base64_encode($encrypted_data),
			'iv' => base64_encode($iv),
			'tag' => base64_encode($tag)
		];
	} catch (Exception $e) {
		error_log("Exception en encryptMessage: " . $e->getMessage());
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}

/**
 * Descifra un mensaje usando la clave compartida
 *
 * @param string $encrypted_data Datos cifrados (en formato hex)
 * @param string $iv Vector de inicialización (en formato hex)
 * @param string $tag Tag de autenticación (en formato hex)
 * @return array Resultado de la operación: [message => string] o [error => string]
 */
function decryptMessage($data, $shared_secret_path) {
	try {
		if (!file_exists($shared_secret_path)) {
			return [
				'error' => 'No existe una clave compartida para descifrar'
			];
		}

		# Verificar que GCM esté disponible
		if (!in_array('aes-256-gcm', openssl_get_cipher_methods())) {
			error_log("AES-256-GCM no está disponible para descifrado");
			return [
				'error' => 'El modo de cifrado AES-256-GCM no está disponible en este servidor'
			];
		}

		# Cargar clave compartida
		$shared_secret = base64_decode(file_get_contents($shared_secret_path));

		# Convertir datos de hex a binario
		$encrypted_data = base64_decode($data['encrypted_data']);
		$iv = base64_decode($data['iv']);
		$tag = base64_decode($data['tag']);

		if ($encrypted_data === false || $iv === false || $tag === false) {
			return [
				'error' => 'Formato de datos cifrados inválido'
			];
		}

		# Descifrar usando AES-256-GCM con la clave compartida
		$decrypted = openssl_decrypt(
			$encrypted_data,
			'aes-256-gcm',
			$shared_secret,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		if ($decrypted === false) {
			$error = [];
			while($err = openssl_error_string()) {
				$error[] = $err;
			}
			return [
				'error' => 'Error al descifrar: ' . implode(', ', $error) . '; shared_secret: ' . file_get_contents($shared_secret_path)
			];
		}

		return [
			'message' => $decrypted
		];
	} catch (Exception $e) {
		error_log("Exception en decryptMessage: " . $e->getMessage());
		return [
			'error' => 'Error: ' . $e->getMessage()
		];
	}
}
