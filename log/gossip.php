<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Gossip de checkpoints y detección de vista dividida (§12.3).
//
// Una autoridad central puede mostrar vistas distintas del log a distintos
// usuarios, y ningún observador aislado lo notaría: cada uno ve un log
// coherente. Lo que lo delata es comparar lo que han visto varios. Por eso la
// especificación dice que los nodos ligeros DEBERÍAN intercambiar checkpoints
// entre sí y con al menos un auditor, y llama a esto la pieza más importante de
// la sección.
//
// Aquí se entrega un checkpoint que alguien vio antes o en otro sitio, y la
// respuesta dice si encaja con la vista de ahora. Lo que convierte el resultado
// en prueba y no en opinión es que los dos checkpoints llevan la firma del
// propio log: si se contradicen, lo hacen con su firma encima.
//
// Nota de honestidad: preguntarle al log si se ha contradicho solo sirve
// mientras el log conteste. Un log que miente puede negarse a responder, y por
// eso el auditor de scripts/auditar-log.php guarda por su cuenta lo que ha
// visto: ahí la prueba ya no depende de que nadie colabore.
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    $body = json_encode(['error' => 'Método no permitido. Usa POST.']);
    log_response($body);
    echo $body;
    exit;
}

$data = json_decode((string) file_get_contents('php://input'), true);

if (!is_array($data) || !isset($data['checkpoint']) || !is_array($data['checkpoint'])) {
    http_response_code(400);
    $body = json_encode(['error' => 'Hace falta el campo "checkpoint" con un checkpoint firmado.']);
    log_response($body);
    echo $body;
    exit;
}

try {
    $identity = loadOrCreateIdentity('log');
    $theirs = $data['checkpoint'];
    $mine = logLastCheckpoint();

    if ($mine === null || (int) $mine['tree_size'] !== logSize()) {
        $mine = logCheckpoint();
    }

    $consistency = null;
    $smallSize = min((int) ($theirs['tree_size'] ?? 0), (int) $mine['tree_size']);

    if ($smallSize >= 1) {
        $consistency = logConsistencyProof($smallSize);
    }

    $verdict = logCompareCheckpoints($theirs, $mine, $identity['public'], $consistency);

    $body = json_encode([
        'theirs' => $theirs,
        'mine' => $mine,
        'consistency' => $consistency,
        'verdict' => $verdict,
        'split_view_proof' => $verdict['split_view']
            // Las dos firmas juntas son la prueba. Se devuelven agrupadas para
            // que quien la tenga pueda presentarla sin volver a preguntar.
            ? ['a' => $theirs, 'b' => $mine, 'log_public_key' => b64uEncode($identity['public'])]
            : null,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    http_response_code(500);
    error_log('log/gossip: ' . $e->getMessage());
    $body = json_encode(['error' => 'No se pudo comparar: ' . $e->getMessage()]);
}

log_response($body);
echo $body;
