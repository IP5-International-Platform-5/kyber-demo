<?php

require_once __DIR__ . '/cors_headers.php';
require_once __DIR__ . '/config.php';

// Último checkpoint firmado del log, y su identidad pública (§12.3, §12.4).
//
// Es el punto de entrada de todo lo demás: cualquier prueba del log se verifica
// contra la raíz de un checkpoint, y un checkpoint solo vale si quien lo lee
// comprueba la firma con la clave pública del log obtenida por otra vía. Si se
// confía en la clave que entrega el propio log en la misma respuesta, no se ha
// comprobado nada.
header('Content-Type: application/json');

try {
    $identity = loadOrCreateIdentity('log');
    $checkpoint = logLastCheckpoint();

    if ($checkpoint === null || (int) $checkpoint['tree_size'] !== logSize()) {
        // El log se firma cuando hace falta: si ha crecido desde el último
        // checkpoint, se publica uno nuevo antes de contestar.
        $checkpoint = logCheckpoint();
    }

    $body = json_encode([
        'checkpoint' => $checkpoint,
        'log_identity' => [
            'log_id' => nodeId($identity['public']),
            'sig_alg' => SIG_ALG,
            'public_key' => b64uEncode($identity['public']),
            'fingerprint' => identityFingerprint($identity['public']),
        ],
        'tree_size' => logSize(),
        'note' => 'Compara la huella de la identidad del log con la que conozcas por otra vía: '
            . 'una clave que entrega el propio log no demuestra de quién es.',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    http_response_code(500);
    error_log('log/checkpoint: ' . $e->getMessage());
    $body = json_encode(['error' => 'El log no puede firmar ahora mismo']);
}

log_response($body);
echo $body;
