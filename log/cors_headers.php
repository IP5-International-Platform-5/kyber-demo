<?php

// Mismas cabeceras que el resto del demostrador. En un despliegue real el log
// sería un origen distinto y esto no sería `*` (lo dice el README entre lo que
// falta).
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
