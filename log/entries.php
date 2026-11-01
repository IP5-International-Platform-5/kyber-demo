<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Las hojas del log, que son públicas (§12.4): la seguridad no depende de que
// el registro sea secreto, sino de que sea verificable.
//
//   ?from=0&count=50   ventana de lectura
//   ?type=identity     filtra por tipo
header('Content-Type: application/json');

$from = isset($_GET['from']) ? max(0, (int) $_GET['from']) : 0;
$count = isset($_GET['count']) ? min(200, max(1, (int) $_GET['count'])) : 50;
$type = isset($_GET['type']) ? (string) $_GET['type'] : null;

$leaves = logLeaves();

if ($type !== null) {
    $leaves = array_values(array_filter($leaves, function ($leaf) use ($type) {
        return ($leaf['type'] ?? '') === $type;
    }));
}

$body = json_encode([
    'tree_size' => logSize(),
    'from' => $from,
    'count' => $count,
    'filtered_by_type' => $type,
    'entries' => array_slice($leaves, $from, $count),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

log_response($body);
echo $body;
