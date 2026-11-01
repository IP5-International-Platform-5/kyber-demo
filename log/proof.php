<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Prueba de inclusión de una entrada (§12.1): ?seq=<n>
//
// Es el equivalente del `sct` de Certificate Transparency. El handshake la
// exige: una identidad que no viene con prueba de que consta en el log se
// rechaza, y así nadie puede presentar una identidad que no esté publicada.
header('Content-Type: application/json');

$seq = isset($_GET['seq']) ? (int) $_GET['seq'] : -1;

try {
    $inclusion = logInclusionProof($seq);
    $leaves = logLeaves();

    $body = json_encode([
        'leaf' => $leaves[$seq],
        'inclusion' => $inclusion,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    http_response_code(404);
    $body = json_encode(['error' => $e->getMessage()]);
}

log_response($body);
echo $body;
