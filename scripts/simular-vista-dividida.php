<?php

/**
 * Simula un log que mantiene dos vistas (§12.3). HERRAMIENTA DE PRUEBA.
 *
 *   php scripts/simular-vista-dividida.php [--raiz-actual] [--deshacer]
 *
 * Un log honesto se niega a firmar un checkpoint que contradiga el que ya
 * publicó: logCheckpoint() lo comprueba y lanza. Un log que miente no tiene esa
 * comprobación, así que para poder demostrar que la detección funciona hay que
 * fabricar lo que haría ese log: otro checkpoint, firmado con su misma clave,
 * sobre el mismo número de entradas y con otra raíz.
 *
 * Eso es exactamente una vista dividida, y es lo que el auditor tiene que
 * encontrar al comparar con lo que guardó.
 *
 *   --raiz-actual   firma la raíz que el log tiene AHORA, para el caso en que
 *                   alguien le haya reescrito una hoja por detrás
 *   --deshacer      retira el último checkpoint publicado, para dejar el estado
 *                   como estaba al terminar la prueba
 *
 * No forma parte del protocolo y no la usa ningún endpoint. Está aquí porque
 * una defensa que no se ha visto fallar no se ha comprobado.
 */

require_once __DIR__ . '/../libs/transparency.php';

$arguments = array_slice(isset($_SERVER['argv']) ? (array) $_SERVER['argv'] : [], 1);
$useCurrentRoot = in_array('--raiz-actual', $arguments, true);
$undo = in_array('--deshacer', $arguments, true);

$path = logCheckpointPath();
$checkpoints = logCheckpoints();

if (empty($checkpoints)) {
    fwrite(STDERR, "El log todavía no ha publicado ningún checkpoint.\n");
    exit(2);
}

if ($undo) {
    array_pop($checkpoints);
    $text = '';

    foreach ($checkpoints as $checkpoint) {
        $text .= canonicalJson($checkpoint) . "\n";
    }

    if (@file_put_contents($path, $text, LOCK_EX) === false) {
        fwrite(STDERR, "No se puede reescribir el fichero de checkpoints.\n");
        exit(2);
    }

    fwrite(STDOUT, 'Retirado el último checkpoint. Quedan ' . count($checkpoints) . ".\n");
    exit(0);
}

$last = $checkpoints[count($checkpoints) - 1];
$identity = loadOrCreateIdentity('log');

$body = [
    'acts_root' => (string) $last['acts_root'],
    // La otra vista: o la que el log tiene ahora mismo tras una reescritura, o
    // una inventada. En los dos casos, el mismo número de entradas que la
    // vista anterior, que es lo que lo convierte en contradicción y no en
    // crecimiento.
    'root' => $useCurrentRoot ? logRoot((int) $last['tree_size']) : hash('sha3-256', 'la otra vista del log'),
    'seq' => (int) $last['seq'] + 1,
    'tree_size' => (int) $last['tree_size'],
    'ts' => rfc3339(),
];

$forged = $body + [
    'log_id' => nodeId($identity['public']),
    'sig_alg' => SIG_ALG,
    'signature' => b64uEncode(signDomain($identity['private'], LOG_CHECKPOINT_DOMAIN, canonicalJson($body))),
];

if (@file_put_contents($path, canonicalJson($forged) . "\n", FILE_APPEND | LOCK_EX) === false) {
    fwrite(STDERR, "No se puede escribir el fichero de checkpoints.\n");
    exit(2);
}

fwrite(STDOUT, "Publicado un checkpoint que contradice al anterior:\n");
fwrite(STDOUT, '  antes:  nº ' . (int) $last['seq'] . ', ' . (int) $last['tree_size']
    . ' entradas, raíz ' . substr((string) $last['root'], 0, 16) . "…\n");
fwrite(STDOUT, '  ahora:  nº ' . (int) $forged['seq'] . ', ' . (int) $forged['tree_size']
    . ' entradas, raíz ' . substr((string) $forged['root'], 0, 16) . "…\n");
fwrite(STDOUT, "\nLos dos llevan la firma del log. Eso es la prueba.\n");
exit(0);
