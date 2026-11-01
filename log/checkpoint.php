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

    if ($checkpoint === null
        || (int) $checkpoint['tree_size'] !== logSize()
        // También cuando la raíz no cuadra con el contenido: un log cuyo
        // fichero cambió sin crecer seguiría entregando una firma que ya no
        // describe lo que tiene, y eso es lo peor de los dos mundos.
        || !hash_equals(strtolower((string) $checkpoint['root']), logRoot())) {
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
    // El motivo sale al cliente a propósito. Si el log no puede firmar porque
    // su contenido contradice lo que ya firmó, eso es justo lo que un auditor
    // tiene que poder leer: un log público que se calla por qué calla no sirve.
    http_response_code(500);
    error_log('log/checkpoint: ' . $e->getMessage());
    $body = json_encode([
        'error' => 'El log no puede firmar ahora mismo',
        'detail' => $e->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

log_response($body);
echo $body;
