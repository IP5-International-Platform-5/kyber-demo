<?php
# Archivo de configuración para almacenar las rutas de los archivos de claves
define('REQUESTS_LOG', __DIR__ . '/../logs/requests.log');
define('KEYS_DIR', __DIR__ . '/keys');
define('PUBLIC_KEY_PATH', KEYS_DIR . '/public.key');
define('PRIVATE_KEY_PATH', KEYS_DIR . '/private.key');
define('SHARED_SECRET_PATH', KEYS_DIR . '/shared_secret.key');

# Crear directorio de claves si no existe
if (!file_exists(KEYS_DIR)) {
    mkdir(KEYS_DIR, 0770, true);
}

# Guarda un registro de petición
function log_request($message) {
    $date = date('Y-m-d H:i:s');
    $logMessage = "[$date] $message\n";
    file_put_contents(REQUESTS_LOG, $logMessage, FILE_APPEND | LOCK_EX);
}

log_request("({$_SERVER['REMOTE_ADDR']}) {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']} " . file_get_contents('php://input'));