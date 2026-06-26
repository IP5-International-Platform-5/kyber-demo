<?php
# CORS for the user app backend (dev / demos)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Max-Age: 86400'); # Cache preflight for 24 hours
header('Cache-Control: no-cache, no-store, must-revalidate'); # Do not cache API responses

# Handle CORS preflight (OPTIONS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
