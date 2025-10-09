<?php
# Si se ha llegado aquí desde el router porque no se detectó un endpoint válido
header('Content-Type: application/json');

echo json_encode([
    'message' => 'API Kyber Post-Quantum Cryptography',
    'endpoints' => [
        'api_server/get_public_key' => 'Obtener la clave pública del servidor',
        'api_client/get_shared_secret' => 'Crear una clave compartida en el cliente',
        'api_server/set_shared_secret' => 'Enviar la clave compartida al servidor',
        'api_client/encrypt' => 'Cifrar un mensaje usando la clave compartida (cliente)',
        'api_server/decrypt' => 'Descifrar un mensaje usando la clave compartida (servidor)'
    ],
    'compatible_endpoints' => [
        'get_public_key' => 'Redirige a api_server/get_public_key',
        'get_shared_secret' => 'Redirige a api_client/get_shared_secret',
        'set_shared_secret' => 'Redirige a api_server/set_shared_secret',
        'encrypt' => 'Redirige a api_client/encrypt',
        'decrypt' => 'Redirige a api_server/decrypt'
    ],
    'documentation' => 'Ver README.md para más información'
]);