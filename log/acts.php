<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Actos de autoridad contra un nodo, con prueba de inclusión o de NO inclusión
// (§12.2, §19.5): ?node_id=ip5:…
//
// La respuesta interesante es la vacía: con el árbol disperso, «no hay ningún
// acto contra este nodo» deja de ser una afirmación del operador y pasa a ser
// algo que se comprueba contra una raíz firmada. Es lo que permite al nodo
// central acusado de censura demostrar que no censuró.
header('Content-Type: application/json');

$nodeId = isset($_GET['node_id']) ? trim((string) $_GET['node_id']) : '';

if ($nodeId === '' || preg_match('/^ip5:[A-Z2-7]{26}$/', $nodeId) !== 1) {
    http_response_code(400);
    $body = json_encode(['error' => 'Hace falta un "node_id" con la forma de la §5.1 (ip5: y 26 caracteres en base32).']);
} else {
    try {
        $proof = actsProofFor($nodeId);

        if ($proof['checkpoint'] === null
            || (int) $proof['checkpoint']['tree_size'] !== logSize()
            || !hash_equals(strtolower((string) $proof['checkpoint']['root']), logRoot())) {
            // La prueba cuelga de una raíz firmada, así que si el log ha
            // crecido hay que firmar antes de contestar.
            logCheckpoint();
            $proof = actsProofFor($nodeId);
        }

        $body = json_encode($proof, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        http_response_code(500);
        error_log('log/acts: ' . $e->getMessage());
        $body = json_encode(['error' => 'No se pudo construir la prueba']);
    }
}

log_response($body);
echo $body;
