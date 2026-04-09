<?php
# User application backend: paths for keys and logs (same process as the front in this demo)
define('REQUESTS_LOG', __DIR__ . '/../logs/requests.log');
define('KEYS_DIR', __DIR__ . '/keys');
# Kyber + AES shared secret for this app (in production, only on this host with the front)
define('SHARED_SECRET_PATH', KEYS_DIR . '/shared_secret.key');

# Create keys directory if missing
if (!file_exists(KEYS_DIR)) {
    mkdir(KEYS_DIR, 0770, true);
}

# Append one line to the request log
function log_request($message) {
    $date = date('Y-m-d H:i:s');
    $logMessage = "[$date] $message\n";
    file_put_contents(REQUESTS_LOG, $logMessage, FILE_APPEND | LOCK_EX);
}

# Do not read php://input here: in some setups it empties the body before POST handlers run
log_request("({$_SERVER['REMOTE_ADDR']}) {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']}");
