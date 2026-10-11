<?php

/**
 * Diario local a prueba de manipulación, con encadenamiento de hashes (§19.2).
 *
 * Lo llevan los dos roles, y eso es lo importante: una auditoría que solo puede
 * examinar al nodo central deja al nodo ligero en condición de alegar y sin
 * nada que probar. Con un diario propio y checkpoints que él mismo firma y
 * publica, la parte débil tiene evidencia.
 *
 * Lo que esto consigue no es inmutabilidad: un fichero siempre se puede
 * reescribir. Cada entrada se compromete con el hash de la anterior y, cada
 * cierto tiempo, el nodo firma un checkpoint sobre la cabeza de la cadena.
 * Reescribir la historia produce entonces una cadena que contradice un
 * checkpoint firmado por él mismo: la manipulación no se impide, **se hace
 * detectable y demostrable**, que es lo que un auditor necesita.
 *
 * El diario guarda hashes, identificadores y firmas. Nunca texto en claro ni
 * material de clave (§15.2, §19.2).
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/merkle.php';
require_once __DIR__ . '/identity.php';

if (!defined('JOURNAL_DIR')) {
    define('JOURNAL_DIR', __DIR__ . '/../journal');
}

if (!defined('JOURNAL_DOMAIN')) {
    define('JOURNAL_DOMAIN', 'QSLP1-demo CKPT');
}

// Valores por defecto de la §19.2: un checkpoint cada 1000 entradas o cada
// hora, lo que llegue primero. Bájalos por entorno para ver el mecanismo
// funcionar sin escribir mil entradas.
if (!defined('CHECKPOINT_EVERY')) {
    define('CHECKPOINT_EVERY', (int) (getenv('QSLP_CHECKPOINT_EVERY') ?: 1000));
}

if (!defined('CHECKPOINT_SECONDS')) {
    define('CHECKPOINT_SECONDS', (int) (getenv('QSLP_CHECKPOINT_SECONDS') ?: 3600));
}

// La primera entrada no encadena con nada, y lo dice con un valor fijo en lugar
// de con un campo vacío, que se confundiría con un campo que falta.
if (!defined('JOURNAL_GENESIS')) {
    define('JOURNAL_GENESIS', str_repeat('0', 64));
}

/**
 * @param string $side "app" o "srv"
 *
 * @return string
 */
function journalPath($side)
{
    return JOURNAL_DIR . '/' . journalSide($side) . '.jsonl';
}

/**
 * @param string $side
 *
 * @return string
 */
function journalCheckpointPath($side)
{
    return JOURNAL_DIR . '/' . journalSide($side) . '.checkpoints.jsonl';
}

/**
 * Rechaza cualquier cosa que no sea uno de los dos roles, para que por este
 * parámetro no se pueda escribir fuera del directorio del diario.
 *
 * @param string $side
 *
 * @return string
 */
function journalSide($side)
{
    if ($side !== 'app' && $side !== 'srv') {
        throw new InvalidArgumentException('El lado del diario tiene que ser "app" o "srv"');
    }

    return $side;
}

/**
 * @return void
 */
function journalEnsureDir()
{
    if (!is_dir(JOURNAL_DIR) && !@mkdir(JOURNAL_DIR, 0750, true) && !is_dir(JOURNAL_DIR)) {
        throw new RuntimeException('No se puede crear el directorio del diario: ' . JOURNAL_DIR);
    }
}

/**
 * Hash de una entrada, sobre su serialización canónica (§6.1).
 *
 * @param array $entry
 *
 * @return string 64 caracteres hexadecimales
 */
function journalEntryHash(array $entry)
{
    return hash('sha3-256', 'QSLP1-demo JE' . canonicalJson($entry));
}

/**
 * Añade una entrada, bajo bloqueo exclusivo: sin él, dos peticiones a la vez
 * encadenarían con la misma predecesora y bifurcarían el diario en silencio.
 *
 * @param string $side
 * @param string $event Nombre del evento, p. ej. "message_sent"
 * @param string $dataHashHex Hash de aquello de lo que habla el evento, nunca la cosa misma
 *
 * @return array{n: int, prev: string, ts: string, event: string, data_hash: string}
 */
function journalAppend($side, $event, $dataHashHex)
{
    journalSide($side);
    journalEnsureDir();

    if (preg_match('/^[0-9a-f]{64}$/', (string) $dataHashHex) !== 1) {
        throw new InvalidArgumentException('El data_hash del diario son 64 caracteres hexadecimales en minúscula');
    }

    $path = journalPath($side);
    $handle = @fopen($path, 'c+');

    if ($handle === false) {
        throw new RuntimeException('No se puede abrir el diario para escribir: ' . $path);
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('No se puede bloquear el diario: ' . $path);
        }

        $entries = journalParse(stream_get_contents($handle));
        $last = empty($entries) ? null : $entries[count($entries) - 1];

        $entry = [
            'n' => $last === null ? 1 : ((int) $last['n'] + 1),
            'prev' => $last === null ? JOURNAL_GENESIS : journalEntryHash($last),
            'ts' => rfc3339(),
            'event' => (string) $event,
            'data_hash' => strtolower((string) $dataHashHex),
        ];

        fseek($handle, 0, SEEK_END);

        if (fwrite($handle, canonicalJson($entry) . "\n") === false) {
            throw new RuntimeException('No se puede escribir en el diario: ' . $path);
        }

        fflush($handle);
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    return $entry;
}

/**
 * @param string $text
 *
 * @return array<int, array> Entradas en el orden del fichero
 */
function journalParse($text)
{
    $entries = [];

    foreach (explode("\n", (string) $text) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $entry = json_decode($line, true);
        if (is_array($entry)) {
            $entries[] = $entry;
        }
    }

    return $entries;
}

/**
 * @param string $side
 *
 * @return array<int, array>
 */
function journalEntries($side)
{
    $path = journalPath($side);

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    return $text === false ? [] : journalParse($text);
}

/**
 * Recorre la cadena e informa del primer sitio donde deja de cuadrar.
 *
 * @param array<int, array> $entries
 *
 * @return array{ok: bool, entries: int, broken_at: int|null, head: string|null}
 */
function journalVerifyChain(array $entries)
{
    $prev = JOURNAL_GENESIS;
    $expectedN = 1;
    $head = null;

    foreach ($entries as $entry) {
        if (!isset($entry['n'], $entry['prev']) || (int) $entry['n'] !== $expectedN) {
            return ['ok' => false, 'entries' => count($entries), 'broken_at' => $expectedN, 'head' => $head];
        }

        if (!hash_equals($prev, (string) $entry['prev'])) {
            return ['ok' => false, 'entries' => count($entries), 'broken_at' => (int) $entry['n'], 'head' => $head];
        }

        $head = journalEntryHash($entry);
        $prev = $head;
        $expectedN++;
    }

    return ['ok' => true, 'entries' => count($entries), 'broken_at' => null, 'head' => $head];
}

/**
 * Raíz de Merkle de los hashes de entrada hasta $n. El checkpoint se
 * compromete con ella además de con la cabeza, de modo que después se pueda
 * demostrar que una entrada concreta pertenece al diario sin entregar el
 * fichero entero.
 *
 * @param array<int, array> $entries
 *
 * @return string|null
 */
function journalRoot(array $entries)
{
    if (empty($entries)) {
        return null;
    }

    $leaves = [];
    foreach ($entries as $entry) {
        $leaves[] = journalEntryHash($entry);
    }

    return merkleRoot($leaves);
}

/**
 * Firma un checkpoint sobre la cabeza actual y lo publica.
 *
 * En un despliegue completo esto va al log de transparencia (§12); aquí se
 * añade a un fichero local, que es el mismo compromiso con menos público. Para
 * que la manipulación sea detectable, lo que cuenta es que el nodo lo firmara.
 *
 * @param string $side
 *
 * @return array|null El checkpoint, o null si no hay nada con lo que comprometerse
 */
function journalCheckpoint($side)
{
    journalSide($side);
    $entries = journalEntries($side);

    if (empty($entries)) {
        return null;
    }

    $chain = journalVerifyChain($entries);

    if (!$chain['ok']) {
        // Firmar un checkpoint sobre una cadena que ya sabemos rota sería poner
        // nuestra propia firma en una contradicción.
        throw new RuntimeException(
            'No se firma un checkpoint de un diario cuya cadena se rompe en la entrada ' . $chain['broken_at'],
        );
    }

    $identity = loadOrCreateIdentity($side === 'srv' ? 'srv' : 'app');

    $body = [
        'head' => (string) $chain['head'],
        'n' => (int) $entries[count($entries) - 1]['n'],
        'root' => (string) journalRoot($entries),
        'ts' => rfc3339(),
    ];

    $checkpoint = $body + [
        'node_id' => nodeId($identity['public']),
        'sig_alg' => SIG_ALG,
        'signature' => b64uEncode(signDomain($identity['private'], JOURNAL_DOMAIN, canonicalJson($body))),
    ];

    journalEnsureDir();
    $path = journalCheckpointPath($side);

    if (@file_put_contents($path, canonicalJson($checkpoint) . "\n", FILE_APPEND | LOCK_EX) === false) {
        throw new RuntimeException('No se puede escribir el fichero de checkpoints: ' . $path);
    }

    return $checkpoint;
}

/**
 * Firma un checkpoint si la §19.2 dice que toca.
 *
 * @param string $side
 *
 * @return array|null
 */
function journalMaybeCheckpoint($side)
{
    $entries = journalEntries($side);

    if (empty($entries)) {
        return null;
    }

    $n = (int) $entries[count($entries) - 1]['n'];
    $last = journalLastCheckpoint($side);

    if ($last === null) {
        return journalCheckpoint($side);
    }

    $sinceEntries = $n - (int) $last['n'];
    $lastTs = parseRfc3339((string) $last['ts']);
    $sinceSeconds = $lastTs === null ? PHP_INT_MAX : time() - $lastTs;
    $due = $sinceEntries >= CHECKPOINT_EVERY || $sinceSeconds >= CHECKPOINT_SECONDS;

    return $due ? journalCheckpoint($side) : null;
}

/**
 * @param string $side
 *
 * @return array<int, array>
 */
function journalCheckpoints($side)
{
    $path = journalCheckpointPath($side);

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    return $text === false ? [] : journalParse($text);
}

/**
 * @param string $side
 *
 * @return array|null
 */
function journalLastCheckpoint($side)
{
    $checkpoints = journalCheckpoints($side);

    return empty($checkpoints) ? null : $checkpoints[count($checkpoints) - 1];
}

/**
 * Primer checkpoint publicado que ya cubre la entrada $n: el que fija la
 * historia que contiene el hecho que se quiere probar.
 *
 * @param string $side
 * @param int $n
 *
 * @return array|null
 */
function journalCheckpointCovering($side, $n)
{
    foreach (journalCheckpoints($side) as $checkpoint) {
        if (isset($checkpoint['n']) && (int) $checkpoint['n'] >= $n) {
            return $checkpoint;
        }
    }

    return null;
}

/**
 * Comprueba la firma de un checkpoint contra una identidad.
 *
 * @param array $checkpoint
 * @param string $publicKey Clave pública ML-DSA cruda del nodo que lo firmó
 *
 * @return bool
 */
function journalVerifyCheckpoint(array $checkpoint, $publicKey)
{
    foreach (['head', 'n', 'root', 'ts', 'signature'] as $field) {
        if (!isset($checkpoint[$field])) {
            return false;
        }
    }

    $signature = b64uDecode((string) $checkpoint['signature']);

    if ($signature === false) {
        return false;
    }

    $body = [
        'head' => (string) $checkpoint['head'],
        'n' => (int) $checkpoint['n'],
        'root' => (string) $checkpoint['root'],
        'ts' => (string) $checkpoint['ts'],
    ];

    return verifyDomain($publicKey, JOURNAL_DOMAIN, canonicalJson($body), $signature);
}

/**
 * Prueba de consistencia entre un checkpoint anterior y otro posterior (§19.3).
 *
 * El RFC 6962 lo hace en log(n) hashes. Aquí es la tirada de entradas que hay
 * entre las dos cabezas: como cada entrada se compromete con el hash de su
 * predecesora, repetirlas desde la cabeza anterior y llegar a la posterior
 * demuestra que el prefijo no se reescribió por el camino. Es lineal en vez de
 * logarítmica, que un diario del tamaño de un demostrador puede permitirse y un
 * registro en producción no.
 *
 * @param string $side
 * @param array $from Checkpoint anterior
 * @param array|null $to Checkpoint posterior; por omisión, el más reciente
 *
 * @return array|null
 */
function journalConsistencyProof($side, array $from, ?array $to = null)
{
    $to = $to === null ? journalLastCheckpoint($side) : $to;

    if ($to === null || !isset($from['n'], $to['n'])) {
        return null;
    }

    if ((int) $to['n'] < (int) $from['n']) {
        return null;
    }

    $entries = [];
    foreach (journalEntries($side) as $entry) {
        $n = (int) $entry['n'];
        if ($n > (int) $from['n'] && $n <= (int) $to['n']) {
            $entries[] = $entry;
        }
    }

    return [
        'kind' => 'tirada de la cadena de hashes entre dos checkpoints firmados',
        'from' => $from,
        'to' => $to,
        'entries' => $entries,
    ];
}

/**
 * Prueba de inclusión de una entrada del diario contra la raíz de un checkpoint.
 *
 * Para esto el checkpoint se compromete con una raíz de Merkle y no solo con la
 * cabeza. Con ella, "la entrada n está en el diario que firmé" son log2(n)
 * hashes; con la cabeza sola habría que entregar el fichero entero, lo que
 * además filtra todas las demás entradas y vuelve inmanejable la evidencia.
 *
 * @param string $side
 * @param int $n Entrada que se quiere probar
 * @param int $upTo Tamaño del checkpoint contra el que se construye la prueba
 *
 * @return array|null
 */
function journalInclusionProof($side, $n, $upTo)
{
    $n = (int) $n;
    $upTo = (int) $upTo;

    if ($n < 1 || $upTo < $n) {
        return null;
    }

    $leaves = [];
    foreach (journalEntries($side) as $entry) {
        if ((int) $entry['n'] <= $upTo) {
            $leaves[] = journalEntryHash($entry);
        }
    }

    if (count($leaves) < $upTo) {
        // El diario ya no tiene todas las entradas que cubría el checkpoint.
        return null;
    }

    return [
        'n' => $n,
        'index' => $n - 1,
        'size' => count($leaves),
        'path' => merkleProof($leaves, $n - 1),
        'root' => merkleRoot($leaves),
    ];
}
