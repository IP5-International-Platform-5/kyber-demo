<?php

# Key material lives in the ephemeral store, never on disk (QSLP/1 §15.4).
require_once __DIR__ . '/../libs/session_store.php';
define('REQUESTS_LOG', __DIR__ . '/../logs/requests.log');


# Append one line to the request log
function log_request($message) {
    $date = date('Y-m-d H:i:s');
    $logMessage = "[$date] $message\n";
    # A log that cannot be written must never break the response. Without the
    # silencing operator, PHP prints a warning before the headers go out, and
    # every endpoint starts answering HTML followed by JSON, with its status
    # code stuck at 200. Errors to the client are codes, never PHP notices
    # (QSLP/1 §15.6).
    if (@file_put_contents(REQUESTS_LOG, $logMessage, FILE_APPEND | LOCK_EX) === false) {
        error_log('kyber: request log is not writable: ' . REQUESTS_LOG);
    }
}

# Build a log-safe view of a JSON response body.
# Whitelist, not blacklist: any field not listed here is replaced by its length,
# so a field added later cannot leak by omission. Key material and plaintext
# must never reach the log, which is a plain file kept alongside the source IP.
function redact_response($body) {
    $visible = ['error', 'status', 'public_key_length'];

    $data = json_decode($body, true);
    if (!is_array($data)) {
        return '[non-JSON body, ' . strlen($body) . ' bytes]';
    }

    $safe = [];
    foreach ($data as $key => $value) {
        if (in_array($key, $visible, true) && is_scalar($value)) {
            $safe[$key] = $value;
        } elseif (is_scalar($value)) {
            $safe[$key] = '[redacted, ' . strlen((string) $value) . ' bytes]';
        } else {
            $safe[$key] = '[redacted]';
        }
    }

    return json_encode($safe, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

# Log a response without writing secrets to disk
function log_response($body) {
    log_request('RESPONSE: ' . redact_response($body));
}

# Do not read php://input here: in some setups it empties the body before POST handlers run
log_request("({$_SERVER['REMOTE_ADDR']}) {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']}");
