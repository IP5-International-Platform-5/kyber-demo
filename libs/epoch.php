<?php

/**
 * Anclaje Merkle por épocas (§11.4).
 *
 * Cada época —60 s por defecto— el nodo central construye un árbol de Merkle
 * con los hashes de los recibos que procesó y ancla *solo la raíz*. Treinta y
 * dos bytes por época: ni mensajes, ni metadatos, ni identificadores
 * personales en la cadena, que es lo que hace esto compatible con la §14.1 en
 * lugar de un problema de RGPD con una cadena al lado. Cualquier nodo puede
 * luego demostrar que su mensaje estaba incluido con log2(n) hashes, sin ver
 * los de los demás.
 *
 * No hay ninguna cadena IP5 donde anclar. Antes que disimularlo, el anclaje
 * queda detrás de una interfaz: la implementación local escribe la raíz en el
 * diario encadenado y la hace firmar en un checkpoint, que es un compromiso
 * real con menos público. El paquete de evidencia declara `"chain": "local"`
 * para que nadie lo confunda con un anclaje en cadena. Sustituirlo por una
 * implementación contra una cadena toca este fichero y ninguno más.
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/merkle.php';
require_once __DIR__ . '/journal.php';
require_once __DIR__ . '/timestamp.php';

if (!defined('EPOCH_SECONDS')) {
    define('EPOCH_SECONDS', (int) (getenv('QSLP_EPOCH_SECONDS') ?: 60));
}

if (!defined('EPOCH_DIR')) {
    define('EPOCH_DIR', __DIR__ . '/../journal/epochs');
}

/**
 * Dónde se puede anclar una raíz. Es la única parte de la §11.4 que depende de
 * una infraestructura que este demostrador no tiene.
 */
interface AnchorBackend
{
    /**
     * @param int $epoch
     * @param string $rootHex
     *
     * @return array<string, mixed> Referencia del anclaje, tal como aparecerá en la evidencia
     */
    public function anchor($epoch, $rootHex);

    /**
     * @return string
     */
    public function name();
}

/**
 * Ancla en el diario local encadenado, que después fija un checkpoint firmado.
 * Honesto con lo que es: no es una cadena, y no pretende serlo.
 */
class LocalJournalAnchor implements AnchorBackend
{
    public function anchor($epoch, $rootHex)
    {
        $entry = journalAppend('srv', 'epoch_anchored', $rootHex);

        return [
            'chain' => 'local',
            'backend' => $this->name(),
            'epoch' => (int) $epoch,
            'journal_n' => (int) $entry['n'],
            'entry_hash' => journalEntryHash($entry),
            'note' => 'Anclado en el diario local encadenado, no en una cadena de bloques: '
                . 'este demostrador no tiene cadena IP5. La §11.4 exige la raíz en cadena.',
        ];
    }

    public function name()
    {
        return 'journal-srv';
    }
}

/**
 * @return AnchorBackend
 */
function anchorBackend()
{
    // Hoy hay una sola implementación. El punto de elección existe para que
    // añadir una contra cadena sea un cambio aquí y no en todas partes.
    return new LocalJournalAnchor();
}

/**
 * @param int|null $ts
 *
 * @return int Número de época
 */
function epochOf($ts = null)
{
    return intdiv($ts === null ? time() : (int) $ts, EPOCH_SECONDS);
}

/**
 * Época a la que pertenece un recibo que llega ahora.
 *
 * Normalmente es la actual. No lo es cuando la época en curso ya se ancló,
 * algo que pasa cuando alguien la cierra antes de tiempo para enseñar el
 * mecanismo: un árbol anclado no debe cambiar —en eso consiste—, así que el
 * recibo entra en la siguiente época abierta en lugar de ser rechazado.
 * Cerrar antes de tiempo adelanta la frontera; nunca deja al nodo incapaz de
 * aceptar mensajes durante el resto del minuto.
 *
 * @param int|null $ts
 *
 * @return int
 */
function epochForReceipt($ts = null)
{
    $epoch = epochOf($ts);

    // Acotado: solo avanza por épocas que se cerraron antes de tiempo, y no
    // puede haber muchas sin que alguien las haya pedido.
    while (epochIsClosed($epoch)) {
        $epoch++;
    }

    return $epoch;
}

/**
 * @param int $epoch
 *
 * @return string
 */
function epochLeavesPath($epoch)
{
    return EPOCH_DIR . '/' . (int) $epoch . '.leaves';
}

/**
 * @param int $epoch
 *
 * @return string
 */
function epochRecordPath($epoch)
{
    return EPOCH_DIR . '/' . (int) $epoch . '.json';
}

/**
 * @return void
 */
function epochEnsureDir()
{
    if (!is_dir(EPOCH_DIR) && !@mkdir(EPOCH_DIR, 0750, true) && !is_dir(EPOCH_DIR)) {
        throw new RuntimeException('No se puede crear el directorio de épocas: ' . EPOCH_DIR);
    }
}

/**
 * Añade un hash de recibo a la época en curso.
 *
 * El orden importa y es el de llegada: es contra él contra el que se construye
 * la prueba de inclusión. Los duplicados se descartan, porque el mismo recibo
 * dos veces haría que el árbol no cuadrase con el registro.
 *
 * @param int $epoch
 * @param string $rcHashHex
 *
 * @return int Posición de la hoja, empezando en cero
 */
function epochAddLeaf($epoch, $rcHashHex)
{
    epochEnsureDir();

    if (preg_match('/^[0-9a-f]{64}$/', (string) $rcHashHex) !== 1) {
        throw new InvalidArgumentException('Una hoja de época son 64 caracteres hexadecimales en minúscula');
    }

    if (epochIsClosed($epoch)) {
        throw new RuntimeException('La época ' . (int) $epoch . ' ya está anclada: su árbol no puede cambiar');
    }

    $path = epochLeavesPath($epoch);
    $handle = @fopen($path, 'c+');

    if ($handle === false) {
        throw new RuntimeException('No se puede abrir el fichero de hojas de la época: ' . $path);
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('No se puede bloquear el fichero de hojas de la época: ' . $path);
        }

        $leaves = epochParseLeaves(stream_get_contents($handle));
        $existing = array_search($rcHashHex, $leaves, true);

        if ($existing !== false) {
            return (int) $existing;
        }

        fseek($handle, 0, SEEK_END);

        if (fwrite($handle, $rcHashHex . "\n") === false) {
            throw new RuntimeException('No se puede escribir el fichero de hojas de la época: ' . $path);
        }

        fflush($handle);

        return count($leaves);
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

/**
 * @param string $text
 *
 * @return string[]
 */
function epochParseLeaves($text)
{
    $leaves = [];

    foreach (explode("\n", (string) $text) as $line) {
        $line = trim($line);
        if (preg_match('/^[0-9a-f]{64}$/', $line) === 1) {
            $leaves[] = $line;
        }
    }

    return $leaves;
}

/**
 * @param int $epoch
 *
 * @return string[]
 */
function epochLeaves($epoch)
{
    $path = epochLeavesPath($epoch);

    if (!is_file($path)) {
        return [];
    }

    $text = @file_get_contents($path);

    return $text === false ? [] : epochParseLeaves($text);
}

/**
 * @param int $epoch
 *
 * @return bool
 */
function epochIsClosed($epoch)
{
    return is_file(epochRecordPath($epoch));
}

/**
 * @param int $epoch
 *
 * @return array|null El registro de la época anclada
 */
function epochRecord($epoch)
{
    $path = epochRecordPath($epoch);

    if (!is_file($path)) {
        return null;
    }

    $text = @file_get_contents($path);

    if ($text === false) {
        return null;
    }

    $record = json_decode($text, true);

    return is_array($record) ? $record : null;
}

/**
 * Cierra una época: construye la raíz, la sella, la ancla y hace que el nodo
 * firme un checkpoint que cubra la entrada del anclaje.
 *
 * Anclar fuerza un checkpoint aunque la §19.2 todavía no lo pidiera. Una raíz
 * que nadie ha firmado es un número en un fichero; la firma es lo que la
 * convierte en evidencia.
 *
 * @param int $epoch
 *
 * @return array|null El registro, o null si la época no tuvo recibos
 */
function epochClose($epoch)
{
    $epoch = (int) $epoch;

    if (epochIsClosed($epoch)) {
        return epochRecord($epoch);
    }

    $leaves = epochLeaves($epoch);

    if (empty($leaves)) {
        // Una época sin recibos no tiene raíz. Anclar un relleno dejaría en el
        // registro un compromiso con nada.
        return null;
    }

    $root = merkleRoot($leaves);

    $record = [
        'epoch' => $epoch,
        'epoch_seconds' => EPOCH_SECONDS,
        'size' => count($leaves),
        'root' => $root,
        'leaves' => $leaves,
        'closed_at' => rfc3339(),
        'timestamp' => tsaStamp(merkleRawFromHex($root)),
        'anchor' => anchorBackend()->anchor($epoch, $root),
    ];

    $record['checkpoint'] = journalCheckpoint('srv');

    epochEnsureDir();

    if (@file_put_contents(epochRecordPath($epoch), canonicalJson($record), LOCK_EX) === false) {
        throw new RuntimeException('No se puede escribir el registro de la época: ' . epochRecordPath($epoch));
    }

    return $record;
}

/**
 * Cierra todas las épocas que ya han terminado.
 *
 * Este demostrador no tiene planificador, así que el cierre es oportunista: lo
 * paga quien toque el nodo a continuación. En un despliegue real esto corre con
 * un temporizador, y entonces los 60 s de la §11.4 son 60 s.
 *
 * @param int|null $now
 *
 * @return array<int, array> Registros escritos, por época
 */
function epochClosePending($now = null)
{
    $current = epochOf($now);
    $closed = [];

    if (!is_dir(EPOCH_DIR)) {
        return $closed;
    }

    foreach ((array) glob(EPOCH_DIR . '/*.leaves') as $path) {
        $epoch = (int) basename((string) $path, '.leaves');

        if ($epoch >= $current || epochIsClosed($epoch)) {
            continue;
        }

        $record = epochClose($epoch);

        if ($record !== null) {
            $closed[$epoch] = $record;
        }
    }

    ksort($closed);

    return $closed;
}

/**
 * Cierra todas las épocas con recibos sin anclar, incluida la que está en
 * curso. Solo para demostrar: una época más corta es un árbol más pequeño, no
 * un protocolo distinto.
 *
 * @return array<int, array>
 */
function epochCloseAll()
{
    $closed = epochClosePending();

    if (!is_dir(EPOCH_DIR)) {
        return $closed;
    }

    foreach ((array) glob(EPOCH_DIR . '/*.leaves') as $path) {
        $epoch = (int) basename((string) $path, '.leaves');

        if (epochIsClosed($epoch)) {
            continue;
        }

        $record = epochClose($epoch);

        if ($record !== null) {
            $closed[$epoch] = $record;
        }
    }

    ksort($closed);

    return $closed;
}

/**
 * Prueba de inclusión de un recibo contra la raíz anclada de su época.
 *
 * @param int $epoch
 * @param string $rcHashHex
 *
 * @return array|null
 */
function epochProofFor($epoch, $rcHashHex)
{
    $record = epochRecord($epoch);
    $leaves = $record === null ? epochLeaves($epoch) : (array) $record['leaves'];
    $index = array_search(strtolower((string) $rcHashHex), $leaves, true);

    if ($index === false) {
        return null;
    }

    return [
        'epoch' => (int) $epoch,
        'index' => (int) $index,
        'size' => count($leaves),
        'path' => merkleProof($leaves, (int) $index),
        'root' => $record === null ? merkleRoot($leaves) : (string) $record['root'],
        'anchored' => $record !== null,
    ];
}
