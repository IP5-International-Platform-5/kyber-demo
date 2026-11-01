<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Prueba de consistencia entre un tamaño anterior y el actual: ?from_size=<n>
//
// Esto es lo que demuestra que el log no reescribió su historia: que el árbol
// de ahora contiene al de antes como prefijo. Logarítmica, como el RFC 6962, y
// no la tirada lineal de entradas que usaba el diario del paso 5.
header('Content-Type: application/json');

$fromSize = isset($_GET['from_size']) ? (int) $_GET['from_size'] : 0;
$proof = logConsistencyProof($fromSize);

if ($proof === null) {
    http_response_code(400);
    $body = json_encode([
        'error' => 'from_size tiene que estar entre 1 y ' . logSize(),
    ]);
} else {
    $body = json_encode($proof, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

log_response($body);
echo $body;
