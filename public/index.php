<?php
# Reached here when no valid endpoint was matched
header('Content-Type: application/json');

echo json_encode([
    'message' => 'Kyber Post-Quantum Cryptography API',
    'endpoints' => [
        'api_server/get_public_key' => 'Get the server public key',
        'app/get_shared_secret' => 'Create a shared secret (user app backend)',
        'api_server/set_shared_secret' => 'Send the Kyber ciphertext to the server',
        'app/encrypt_message' => 'Encrypt a message with the shared secret (user app backend)',
        'api_server/decrypt_message' => 'Decrypt a message with the shared secret (server)'
    ],
    'compatible_endpoints' => [
        'get_public_key' => 'Forwards to api_server/get_public_key',
        'get_shared_secret' => 'Forwards to app/get_shared_secret',
        'set_shared_secret' => 'Forwards to api_server/set_shared_secret',
        'encrypt' => 'Forwards to app/encrypt_message',
        'decrypt' => 'Forwards to api_server/decrypt_message'
    ],
    'documentation' => 'See README.md for details'
]);
