<?php

// Log de transparencia (§12): rol propio, identidad propia.
//
// Comparte máquina con el nodo central y con la aplicación, porque esto es un
// demostrador, pero no comparte claves: los checkpoints los firma la identidad
// `log` y nadie más puede fabricarlos. Esa es la propiedad que hace útil al log
// frente a un nodo central abusivo (A4); la separación física es otra cosa, y
// no la tenemos.
require_once __DIR__ . '/../libs/transparency.php';

define('REQUESTS_LOG', __DIR__ . '/../logs/requests.log');

/**
 * Añade una línea al registro de peticiones.
 *
 * @param string $message
 *
 * @return void
 */
function log_request($message)
{
    $date = date('Y-m-d H:i:s');

    // Un registro que no se puede escribir nunca debe romper la respuesta: sin
    // el silenciador, PHP imprime un aviso antes de las cabeceras y el endpoint
    // acaba devolviendo HTML seguido de JSON con un 200 pegado (§15.6).
    if (@file_put_contents(REQUESTS_LOG, "[$date] $message\n", FILE_APPEND | LOCK_EX) === false) {
        error_log('kyber: el registro de peticiones no es escribible: ' . REQUESTS_LOG);
    }
}

/**
 * El log de transparencia es público por definición (§12.4): lo que responde
 * son hashes, firmas y claves públicas, así que aquí no hay nada que redactar.
 * Se registra el tamaño y nada más, para no duplicar el log dentro del log.
 *
 * @param string $body
 *
 * @return void
 */
function log_response($body)
{
    log_request('RESPONSE: ' . strlen($body) . ' bytes');
}

log_request("({$_SERVER['REMOTE_ADDR']}) {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']}");
