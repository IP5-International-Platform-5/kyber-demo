<?php

/**
 * Auditor del log de transparencia (§12.3).
 *
 *   php scripts/auditar-log.php [http://localhost:8080] [--reiniciar]
 *
 * Un log que se audita a sí mismo no se audita. Este programa hace lo que la
 * especificación pide de «al menos un auditor»: **guarda por su cuenta** cada
 * checkpoint firmado que ha visto y, en cada visita, exige al log que demuestre
 * que su vista de ahora contiene la de antes. Si no puede demostrarlo, el
 * auditor emite un informe de vista dividida y se queda con las dos firmas,
 * que son la prueba.
 *
 * Lo importante es dónde vive la memoria: en `auditor/`, que es del auditor y
 * no del log. Si la prueba dependiera de lo que el log conserva, un log que
 * miente podría borrarla.
 *
 * Esto sí usa la red, a diferencia del verificador de evidencia: un auditor
 * tiene que ir a mirar. Lo que no hace es fiarse de nada que no venga firmado.
 *
 * Código de salida: 0 si la vista es consistente, 1 si hay vista dividida o
 * historia reescrita, 2 si no se pudo auditar.
 */

require_once __DIR__ . '/../libs/transparency.php';

if (!defined('AUDITOR_DIR')) {
    define('AUDITOR_DIR', __DIR__ . '/../auditor');
}

$arguments = array_slice(isset($_SERVER['argv']) ? (array) $_SERVER['argv'] : [], 1);
$base = 'http://localhost:8080';
$reset = false;

foreach ($arguments as $argument) {
    if ($argument === '--reiniciar') {
        $reset = true;
    } elseif (strpos($argument, 'http') === 0) {
        $base = rtrim($argument, '/');
    }
}

/**
 * @param string $url
 *
 * @return array<string, mixed>|null
 */
function fetchJson($url)
{
    $context = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
    $body = @file_get_contents($url, false, $context);

    if ($body === false) {
        return null;
    }

    $decoded = json_decode($body, true);

    return is_array($decoded) ? $decoded : null;
}

/**
 * @return string
 */
function seenPath()
{
    return AUDITOR_DIR . '/checkpoints-vistos.jsonl';
}

/**
 * @return array<int, array>
 */
function seenCheckpoints()
{
    if (!is_file(seenPath())) {
        return [];
    }

    $text = (string) @file_get_contents(seenPath());
    $seen = [];

    foreach (explode("\n", $text) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $decoded = json_decode($line, true);
        if (is_array($decoded)) {
            $seen[] = $decoded;
        }
    }

    return $seen;
}

/**
 * @param array $checkpoint
 *
 * @return void
 */
function remember(array $checkpoint)
{
    if (!is_dir(AUDITOR_DIR) && !@mkdir(AUDITOR_DIR, 0755, true) && !is_dir(AUDITOR_DIR)) {
        fwrite(STDERR, 'No se puede crear el directorio del auditor: ' . AUDITOR_DIR . "\n");

        return;
    }

    @file_put_contents(seenPath(), canonicalJson($checkpoint) . "\n", FILE_APPEND | LOCK_EX);
}

if ($reset && is_file(seenPath())) {
    @unlink(seenPath());
    fwrite(STDOUT, "Memoria del auditor borrada.\n");
}

fwrite(STDOUT, "\nAUDITORÍA DEL LOG DE TRANSPARENCIA — QSLP/1 §12.3\n");
fwrite(STDOUT, str_repeat('=', 72) . "\n\n");

$answer = fetchJson($base . '/log/checkpoint');

if ($answer === null || !isset($answer['checkpoint'], $answer['log_identity']['public_key'])) {
    fwrite(STDERR, "El log de $base no contesta un checkpoint utilizable.\n");
    exit(2);
}

$current = $answer['checkpoint'];
$logKey = b64uDecode((string) $answer['log_identity']['public_key']);

if ($logKey === false) {
    fwrite(STDERR, "La clave pública del log no es base64url válido.\n");
    exit(2);
}

fwrite(STDOUT, 'Log:         ' . (string) $answer['log_identity']['log_id'] . "\n");
fwrite(STDOUT, 'Huella:      ' . (string) $answer['log_identity']['fingerprint'] . "\n");
fwrite(STDOUT, 'Checkpoint:  nº ' . (int) $current['seq'] . ', ' . (int) $current['tree_size']
    . ' entradas, fechado ' . (string) $current['ts'] . "\n\n");

if (!logVerifyCheckpoint($current, $logKey)) {
    fwrite(STDOUT, "[ NO ] El checkpoint no está firmado por la identidad que el log presenta.\n");
    fwrite(STDOUT, "\nUn checkpoint sin firma válida no sirve para nada: no se guarda.\n");
    exit(1);
}

fwrite(STDOUT, "[ SÍ ] El checkpoint está firmado por la identidad que el log presenta.\n");
fwrite(STDOUT, "       Compara la huella con la que conozcas por otra vía: una clave que\n");
fwrite(STDOUT, "       entrega el propio log no demuestra de quién es.\n");

$seen = seenCheckpoints();
$problems = 0;

if (empty($seen)) {
    fwrite(STDOUT, "\n[ -- ] Primera visita: no hay nada anterior con lo que contrastar. A partir\n");
    fwrite(STDOUT, "       de ahora este checkpoint queda guardado en auditor/, fuera del log.\n");
} else {
    $previous = $seen[count($seen) - 1];

    fwrite(STDOUT, "\nContraste con lo que este auditor vio antes (nº " . (int) $previous['seq']
        . ', ' . (int) $previous['tree_size'] . " entradas):\n");

    if ((int) $current['tree_size'] < (int) $previous['tree_size']) {
        // Un log append-only no encoge. Esto ya es prueba por sí solo.
        fwrite(STDOUT, '[ NO ] El log ha ENCOGIDO, de ' . (int) $previous['tree_size'] . ' a '
            . (int) $current['tree_size'] . " entradas.\n");
        fwrite(STDOUT, "       Un log append-only no encoge: con las dos firmas basta.\n");
        $problems++;
    } else {
        $consistency = fetchJson($base . '/log/consistency?from_size=' . (int) $previous['tree_size']);
        $verdict = logCompareCheckpoints($previous, $current, $logKey, $consistency);

        if ($verdict['split_view']) {
            fwrite(STDOUT, "[ NO ] VISTA DIVIDIDA o historia reescrita.\n");
            fwrite(STDOUT, '       ' . wordwrap($verdict['detail'], 64, "\n       ") . "\n");
            $problems++;
        } elseif ($verdict['same_view'] === true) {
            fwrite(STDOUT, "[ SÍ ] La vista de ahora contiene la de antes: el log creció sin\n");
            fwrite(STDOUT, "       reescribir nada.\n");
        } else {
            fwrite(STDOUT, "[ -- ] No se pudo decidir.\n");
            fwrite(STDOUT, '       ' . wordwrap($verdict['detail'], 64, "\n       ") . "\n");
        }
    }

    if ((int) $current['seq'] <= (int) $previous['seq'] && (int) $current['tree_size'] > (int) $previous['tree_size']) {
        fwrite(STDOUT, "[ NO ] El número de secuencia no avanza mientras el log crece: el\n");
        fwrite(STDOUT, "       contador firmado no cuadra con lo que el log publica.\n");
        $problems++;
    }
}

if ($problems === 0) {
    remember($current);
}

fwrite(STDOUT, "\n" . str_repeat('-', 72) . "\n");

if ($problems === 0) {
    fwrite(STDOUT, 'Sin contradicciones. Checkpoint guardado en ' . seenPath() . "\n");
    fwrite(STDOUT, "\nEsto NO acredita que el contenido del log sea cierto, solo que el log no se\n");
    fwrite(STDOUT, "ha contradicho con lo que ya había firmado ante este auditor.\n\n");
    exit(0);
}

fwrite(STDOUT, "$problems contradicción(es). El checkpoint NO se guarda: lo que se conserva es\n");
fwrite(STDOUT, "el anterior, que es el que forma pareja con la prueba.\n");
fwrite(STDOUT, "\nPresenta juntos el checkpoint guardado en " . seenPath() . " y el que acaba de\n");
fwrite(STDOUT, "entregar el log: los dos llevan su firma, y se contradicen.\n\n");
exit(1);
