<?php

/**
 * Verificador de referencia de paquetes de evidencia QSLP/1 (§19.4).
 *
 *   php scripts/verificar-evidencia.php paquete.json [--emisor=ip5:…] [--receptor=ip5:…] [--log-id=ip5:…]
 *
 * Una evidencia que solo sabe verificar quien opera el servidor auditado no es
 * evidencia: es una afirmación con formato JSON. Por eso este programa
 *
 *   1. no hace ninguna petición de red: todo lo que necesita está en el fichero;
 *   2. no comparte una línea de código con los endpoints que generan los
 *      paquetes. La canonicalización, el árbol de Merkle, el base32 y el
 *      encadenamiento del diario están reimplementados aquí a propósito. Si las
 *      dos implementaciones discrepan, hay un fallo, y eso es precisamente lo
 *      que un verificador independiente tiene que poder detectar;
 *   3. enumera qué ha comprobado, qué ha fallado y qué NO comprueba, porque un
 *      informe que solo dice "válido" obliga a creerle.
 *
 * Lo que este programa NO puede decidir, y nadie debería pedirle: si las claves
 * públicas del paquete son de quien dice el paquete. Sin cadena de certificados
 * (§5.3) eso se ata desde fuera, con --emisor y --receptor, comparando contra
 * identidades conocidas por otra vía.
 *
 * Código de salida: 0 si todas las comprobaciones aplicables pasan, 1 si alguna
 * falla, 2 si el fichero no se puede ni leer.
 */

$arguments = array_slice(isset($_SERVER['argv']) ? (array) $_SERVER['argv'] : [], 1);
$file = null;
$expectedSender = null;
$expectedReceiver = null;
$expectedLog = null;

foreach ($arguments as $argument) {
    if (strpos($argument, '--emisor=') === 0) {
        $expectedSender = substr($argument, 9);
    } elseif (strpos($argument, '--receptor=') === 0) {
        $expectedReceiver = substr($argument, 11);
    } elseif (strpos($argument, '--log-id=') === 0) {
        $expectedLog = substr($argument, 9);
    } elseif ($argument === '--ayuda' || $argument === '-h') {
        fwrite(STDOUT, "Uso: php verificar-evidencia.php paquete.json [--emisor=ip5:…] [--receptor=ip5:…] [--log-id=ip5:…]\n");
        exit(0);
    } else {
        $file = $argument;
    }
}

if ($file === null || !is_file($file)) {
    fwrite(STDERR, "No se puede leer el paquete de evidencia. Uso:\n"
        . "  php verificar-evidencia.php paquete.json [--emisor=ip5:…] [--receptor=ip5:…] [--log-id=ip5:…]\n");
    exit(2);
}

$package = json_decode((string) file_get_contents($file), true);

if (!is_array($package)) {
    fwrite(STDERR, "El fichero no contiene JSON válido.\n");
    exit(2);
}

// ---------------------------------------------------------------------------
// Primitivas, reimplementadas aquí por independencia (ver cabecera).
// ---------------------------------------------------------------------------

/**
 * Subconjunto de JCS (RFC 8785): claves de objeto ordenadas, sin espacios.
 * Rechaza flotantes en vez de darles un formato inventado.
 *
 * @param mixed $value
 *
 * @return string
 */
function vCanonical($value)
{
    return json_encode(vSortKeys($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/**
 * @param mixed $value
 *
 * @return mixed
 */
function vSortKeys($value)
{
    if (is_float($value)) {
        throw new RuntimeException('El paquete contiene un número no entero, que este subconjunto de JCS no canonicaliza');
    }

    if (!is_array($value)) {
        return $value;
    }

    if (array_keys($value) === range(0, count($value) - 1)) {
        return array_map('vSortKeys', $value);
    }

    $keys = array_map('strval', array_keys($value));
    sort($keys, SORT_STRING);

    $out = [];
    foreach ($keys as $key) {
        $out[$key] = vSortKeys($value[$key]);
    }

    return $out;
}

/**
 * @param string $text
 *
 * @return string|false
 */
function vB64uDecode($text)
{
    if (!is_string($text) || preg_match('/^[A-Za-z0-9_-]+$/', $text) !== 1) {
        return false;
    }

    return base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
}

/**
 * @param string $raw
 *
 * @return string
 */
function vBase32($raw)
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';

    for ($i = 0; $i < strlen($raw); $i++) {
        $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
    }

    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= $alphabet[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
    }

    return $out;
}

/**
 * Identificador de nodo de la §5.1, con la mitad clásica ausente.
 *
 * @param string $publicKey Clave ML-DSA cruda
 *
 * @return string
 */
function vNodeId($publicKey)
{
    return 'ip5:' . substr(vBase32(hash('sha3-256', $publicKey, true)), 0, 26);
}

/**
 * @param string $hex
 *
 * @return string
 */
function vRawFromHex($hex)
{
    if (!is_string($hex) || preg_match('/^[0-9a-f]{64}$/', $hex) !== 1) {
        throw new RuntimeException('Se esperaba un hash de 64 caracteres hexadecimales');
    }

    return (string) hex2bin($hex);
}

/**
 * Hoja y nodo interno con prefijos distintos (RFC 6962): sin esa separación un
 * nodo interno se puede presentar como hoja y el árbol admite una segunda
 * preimagen.
 *
 * @param string $leafHex
 *
 * @return string
 */
function vLeafHash($leafHex)
{
    return hash('sha3-256', "\x00" . vRawFromHex($leafHex), true);
}

/**
 * @param string $left
 * @param string $right
 *
 * @return string
 */
function vNodeHash($left, $right)
{
    return hash('sha3-256', "\x01" . $left . $right, true);
}

/**
 * Pliega una ruta de inclusión y devuelve la raíz resultante.
 *
 * @param string $leafHex
 * @param array $path
 *
 * @return string Raíz en hexadecimal
 */
function vFoldProof($leafHex, array $path)
{
    $current = vLeafHash($leafHex);

    foreach ($path as $step) {
        if (!is_array($step) || !isset($step['side'], $step['hash'])) {
            throw new RuntimeException('La ruta de inclusión tiene un paso mal formado');
        }

        $sibling = vRawFromHex((string) $step['hash']);

        if ($step['side'] === 'right') {
            $current = vNodeHash($current, $sibling);
        } elseif ($step['side'] === 'left') {
            $current = vNodeHash($sibling, $current);
        } else {
            throw new RuntimeException('La ruta de inclusión indica un lado desconocido: ' . $step['side']);
        }
    }

    return bin2hex($current);
}

/**
 * @param array $entry
 *
 * @return string
 */
function vEntryHash(array $entry)
{
    return hash('sha3-256', 'QSLP1-demo JE' . vCanonical($entry));
}

/**
 * Verificación de firma ML-DSA bajo etiqueta de dominio.
 *
 * @param string $publicKey
 * @param string $domain
 * @param string $message
 * @param string $signatureB64u
 *
 * @return bool|null Null cuando la extensión no está disponible
 */
function vVerifySignature($publicKey, $domain, $message, $signatureB64u)
{
    if (!class_exists('OQS_SIGNATURE')) {
        return null;
    }

    $signature = vB64uDecode((string) $signatureB64u);

    if ($signature === false || $publicKey === '') {
        return false;
    }

    try {
        $verifier = new OQS_SIGNATURE('ML-DSA-65');

        return $verifier->verify(hash('sha3-256', $domain . $message, true), $signature, $publicKey) === OQS_SUCCESS;
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Punto de corte del RFC 6962: mayor potencia de dos menor que $n.
 *
 * @param int $n
 *
 * @return int
 */
function vMerkleSplit($n)
{
    $k = 1;

    while ($k * 2 < $n) {
        $k *= 2;
    }

    return $k;
}

/**
 * @param string[] $proof
 * @param int $cursor
 *
 * @return string
 */
function vTakeProofHash(array $proof, &$cursor)
{
    if (!isset($proof[$cursor])) {
        throw new RuntimeException('La prueba de consistencia se queda corta');
    }

    $raw = vRawFromHex(strtolower((string) $proof[$cursor]));
    $cursor++;

    return $raw;
}

/**
 * Recompone a la vez la raíz antigua y la nueva, consumiendo la prueba en el
 * orden en que se generó.
 *
 * @param int $m
 * @param int $n
 * @param string[] $proof
 * @param int $cursor
 * @param bool $known
 * @param string $rootMRaw
 *
 * @return array{0: string, 1: string}
 */
function vConsistencyFold($m, $n, array $proof, &$cursor, $known, $rootMRaw)
{
    if ($m === $n) {
        if ($known) {
            return [$rootMRaw, $rootMRaw];
        }

        $hash = vTakeProofHash($proof, $cursor);

        return [$hash, $hash];
    }

    $k = vMerkleSplit($n);

    if ($m <= $k) {
        $left = vConsistencyFold($m, $k, $proof, $cursor, $known, $rootMRaw);
        $right = vTakeProofHash($proof, $cursor);

        return [$left[0], vNodeHash($left[1], $right)];
    }

    $right = vConsistencyFold($m - $k, $n - $k, $proof, $cursor, false, $rootMRaw);
    $left = vTakeProofHash($proof, $cursor);

    return [vNodeHash($left, $right[0]), vNodeHash($left, $right[1])];
}

/**
 * Comprueba que el árbol de $m hojas es prefijo del de $n (RFC 6962 §2.1.2).
 *
 * Es lo que distingue «el log creció» de «el log cambió lo que ya había
 * firmado». Sin esta comprobación, dos checkpoints distintos del mismo log no
 * se pueden interpretar: lo normal es que difieran.
 *
 * @param int $m
 * @param int $n
 * @param string[] $proof
 * @param string $rootMHex
 * @param string $rootNHex
 *
 * @return bool
 */
function vConsistencyVerify($m, $n, array $proof, $rootMHex, $rootNHex)
{
    $m = (int) $m;
    $n = (int) $n;

    if ($m < 1 || $n < $m) {
        return false;
    }

    if ($m === $n) {
        return $proof === [] && hash_equals(strtolower($rootMHex), strtolower($rootNHex));
    }

    try {
        $cursor = 0;
        $roots = vConsistencyFold($m, $n, array_values($proof), $cursor, true, vRawFromHex(strtolower($rootMHex)));

        return $cursor === count($proof)
            && hash_equals(strtolower($rootMHex), bin2hex($roots[0]))
            && hash_equals(strtolower($rootNHex), bin2hex($roots[1]));
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Hash de una hoja del log de transparencia. Etiqueta propia, para que no se
 * pueda confundir con una entrada de diario ni con un nodo del árbol.
 *
 * @param array $leaf
 *
 * @return string
 */
function vLogLeafHash(array $leaf)
{
    return hash('sha3-256', 'QSLP1-demo TL' . vCanonical($leaf));
}

/**
 * Hashes de los subárboles vacíos del árbol disperso, por altura. Quien
 * verifica los calcula por su cuenta, y por eso una prueba solo necesita
 * traer los hermanos que no están vacíos.
 *
 * @return string[]
 */
function vSparseDefaults()
{
    static $defaults = null;

    if ($defaults === null) {
        $defaults = [hash('sha3-256', "\x10" . 'QSLP1-demo SMT empty', true)];

        for ($height = 1; $height <= 256; $height++) {
            $defaults[$height] = vSparseNode($defaults[$height - 1], $defaults[$height - 1]);
        }
    }

    return $defaults;
}

/**
 * @param string $left
 * @param string $right
 *
 * @return string
 */
function vSparseNode($left, $right)
{
    return hash('sha3-256', "\x11" . $left . $right, true);
}

/**
 * @param string $keyHex
 * @param string $valueHex
 *
 * @return string
 */
function vSparseLeaf($keyHex, $valueHex)
{
    return hash('sha3-256', "\x12" . vRawFromHex($keyHex) . vRawFromHex($valueHex), true);
}

/**
 * @param string $keyHex
 * @param int $index
 *
 * @return int
 */
function vSparseBit($keyHex, $index)
{
    return (ord(vRawFromHex($keyHex)[intdiv($index, 8)]) >> (7 - ($index % 8))) & 1;
}

/**
 * Pliega una prueba del árbol disperso. Sirve igual para demostrar que algo
 * está y que algo NO está: lo único que cambia es si la hoja lleva valor, y esa
 * simetría es lo que permite demostrar una ausencia (§19.5).
 *
 * @param array $proof
 * @param string $rootHex
 *
 * @return bool
 */
function vSparseVerify($proof, $rootHex)
{
    if (!is_array($proof) || !isset($proof['key'], $proof['bitmap'], $proof['siblings'])) {
        return false;
    }

    try {
        $defaults = vSparseDefaults();
        $keyHex = strtolower((string) $proof['key']);
        $raw = vRawFromHex(strtolower((string) $proof['bitmap']));
        $bits = '';

        for ($i = 0; $i < strlen($raw); $i++) {
            $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
        }

        $siblings = array_values((array) $proof['siblings']);
        $value = $proof['value'] ?? null;
        $current = ($value === null) ? $defaults[0] : vSparseLeaf($keyHex, (string) $value);
        $next = count($siblings) - 1;

        for ($depth = 255; $depth >= 0; $depth--) {
            if ($bits[$depth] === '1') {
                if ($next < 0) {
                    return false;
                }
                $sibling = vRawFromHex(strtolower((string) $siblings[$next]));
                $next--;
            } else {
                $sibling = $defaults[255 - $depth];
            }

            $current = vSparseBit($keyHex, $depth) === 0
                ? vSparseNode($current, $sibling)
                : vSparseNode($sibling, $current);
        }

        // Con hermanos de sobra no es una prueba: es una prueba y algo más.
        return $next === -1 && hash_equals(strtolower((string) $rootHex), bin2hex($current));
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Valor que representa a un sujeto en el árbol de actos: el hash de la lista de
 * hashes de sus actos. Ocultar uno cambia el valor, así que enseñar una lista
 * recortada no cuadra con la raíz firmada.
 *
 * @param array<int, array> $acts
 *
 * @return string
 */
function vActsValue(array $acts)
{
    $hashes = [];

    foreach ($acts as $act) {
        $hashes[] = vLogLeafHash($act);
    }

    return hash('sha3-256', 'QSLP1-demo acts' . vCanonical($hashes));
}

// ---------------------------------------------------------------------------
// Informe
// ---------------------------------------------------------------------------

$checks = [];

/**
 * Cuatro estados, y la diferencia importa: que un paquete no traiga sello de
 * tiempo no es lo mismo que que una firma no cuadre. Lo primero es una
 * carencia declarada del paquete, lo segundo significa que no sostiene lo que
 * afirma. Mezclarlos haría ilegible el informe.
 *
 * @param string $name
 * @param bool|string|null $result true pasa, false falla, 'ausente' es una
 *                                 carencia del paquete, null no se pudo comprobar
 * @param string $detail
 *
 * @return void
 */
function check($name, $result, $detail = '')
{
    global $checks;
    $checks[] = ['nombre' => $name, 'resultado' => $result, 'detalle' => $detail];
}

/**
 * @param array $data
 * @param string $path
 *
 * @return mixed
 */
function field(array $data, $path)
{
    $current = $data;

    foreach (explode('.', $path) as $part) {
        if (!is_array($current) || !array_key_exists($part, $current)) {
            return;
        }
        $current = $current[$part];
    }

    return $current;
}

// --- 1. Estructura -----------------------------------------------------------

check(
    'El fichero se declara paquete de evidencia QSLP/1',
    field($package, 'qslp_evidence') === 1 && field($package, 'spec_version') === 'QSLP/1',
    'qslp_evidence=' . json_encode(field($package, 'qslp_evidence'))
    . ', spec_version=' . json_encode(field($package, 'spec_version'), JSON_UNESCAPED_SLASHES),
);

$core = field($package, 'receipt_core');
$coreFields = ['sid', 'seq', 'from', 'to', 'ts', 'payload_hash', 'th'];
$coreComplete = is_array($core) && array_diff($coreFields, array_keys($core)) === [];

check(
    'receipt_core tiene los siete campos que exige la §11.1',
    $coreComplete,
    $coreComplete ? 'sid, seq, from, to, ts, payload_hash, th' : 'faltan campos: ' . implode(', ', array_diff($coreFields, is_array($core) ? array_keys($core) : [])),
);

if (!$coreComplete) {
    report($checks, $package);
    exit(1);
}

// --- 2. El hash del núcleo ---------------------------------------------------

$computedHash = hash('sha3-256', vCanonical($core));
$declaredHash = strtolower((string) field($package, 'receipt_core_hash'));

check(
    'El hash declarado del receipt_core es el que resulta de recalcularlo',
    hash_equals($computedHash, $declaredHash),
    'calculado ' . substr($computedHash, 0, 16) . '…, declarado ' . substr($declaredHash, 0, 16) . '…',
);

// --- 3. Identidades ----------------------------------------------------------

$senderKey = vB64uDecode((string) field($package, 'identities.sender.public_key'));
$receiverKey = vB64uDecode((string) field($package, 'identities.receiver.public_key'));

check(
    'El paquete trae las dos claves públicas',
    $senderKey !== false && $receiverKey !== false,
    $senderKey === false ? 'falta o está mal codificada la del emisor' : (($receiverKey === false) ? 'falta o está mal codificada la del receptor' : 'ML-DSA-65, emisor y receptor'),
);

if ($senderKey !== false) {
    check(
        'El identificador del emisor se deriva de su clave pública',
        hash_equals(vNodeId($senderKey), (string) $core['from']),
        'from=' . $core['from'] . ', derivado=' . vNodeId($senderKey),
    );
}

if ($receiverKey !== false) {
    check(
        'El identificador del receptor se deriva de su clave pública',
        hash_equals(vNodeId($receiverKey), (string) $core['to']),
        'to=' . $core['to'] . ', derivado=' . vNodeId($receiverKey),
    );
}

if ($expectedSender !== null) {
    check(
        'El emisor es la identidad indicada en la línea de órdenes',
        hash_equals($expectedSender, (string) $core['from']),
        'esperado ' . $expectedSender . ', encontrado ' . $core['from'],
    );
} else {
    check(
        'El emisor es quien el paquete dice que es',
        null,
        'No comprobado: sin --emisor, y sin cadena de certificados (§5.3), nada ata esa clave '
        . 'pública a una persona u organización. Compárala por otra vía.',
    );
}

if ($expectedReceiver !== null) {
    check(
        'El receptor es la identidad indicada en la línea de órdenes',
        hash_equals($expectedReceiver, (string) $core['to']),
        'esperado ' . $expectedReceiver . ', encontrado ' . $core['to'],
    );
}

// --- 4. Las dos firmas -------------------------------------------------------

$senderSignature = field($package, 'signatures.sender.signature');
$senderResult = $senderKey === false ? false : vVerifySignature($senderKey, 'QSLP1-demo RC', vCanonical($core), (string) $senderSignature);

check(
    'La firma del emisor sobre receipt_core verifica (no repudio de origen, §11.1)',
    $senderResult,
    $senderResult === null ? 'No comprobado: falta la extensión oqsphp en este intérprete' : 'ML-DSA-65 sobre el núcleo canónico',
);

$receipt = field($package, 'signatures.receiver_receipt');

if (!is_array($receipt)) {
    check(
        'El acuse de recibo firmado está presente (§11.2)',
        false,
        'Un paquete con una sola firma prueba la mitad: el envío, no la recepción.',
    );
} else {
    $receiptBody = [
        'by' => (string) ($receipt['by'] ?? ''),
        'rc_hash' => strtolower((string) ($receipt['rc_hash'] ?? '')),
        'ts' => (string) ($receipt['ts'] ?? ''),
    ];

    $receiptResult = $receiverKey === false ? false : vVerifySignature($receiverKey, 'QSLP1-demo RCPT', vCanonical($receiptBody), (string) ($receipt['signature'] ?? ''));

    check(
        'La firma del acuse verifica (no repudio de recepción, §11.2)',
        $receiptResult,
        $receiptResult === null ? 'No comprobado: falta la extensión oqsphp' : 'firmado por ' . $receiptBody['by'] . ' el ' . $receiptBody['ts'],
    );

    check(
        'El acuse se refiere a este mismo receipt_core',
        hash_equals($computedHash, $receiptBody['rc_hash']),
        'rc_hash del acuse ' . substr($receiptBody['rc_hash'], 0, 16) . '…',
    );

    check(
        'Quien firma el acuse es el destinatario que el emisor nombró',
        hash_equals((string) $core['to'], $receiptBody['by']),
        'to=' . $core['to'] . ', by=' . $receiptBody['by'],
    );
}

// --- 5. Contenido ------------------------------------------------------------

if (field($package, 'payload.present') === true) {
    $payload = vB64uDecode((string) field($package, 'payload.value'));

    check(
        'El contenido aportado es el que el emisor firmó',
        $payload !== false && hash_equals((string) $core['payload_hash'], hash('sha3-256', $payload)),
        'SHA3-256 del contenido frente a payload_hash',
    );
} else {
    check(
        'El contenido del mensaje',
        'ausente',
        'No incluido en el paquete, y su ausencia está justificada: lo que está firmado es '
        . 'payload_hash. Quien conserve el mensaje puede demostrar que es ése recalculando el hash.',
    );
}

// --- 6. Inclusión en la raíz de época ---------------------------------------

$merkleProof = field($package, 'merkle_proof');

if (!is_array($merkleProof)) {
    check(
        'Prueba de inclusión en la raíz de la época (§11.4)',
        false,
        'Ausente: sin ella no consta que este mensaje estuviera en el árbol anclado.',
    );
} else {
    try {
        $foldedRoot = vFoldProof($declaredHash, (array) ($merkleProof['path'] ?? []));
        check(
            'La prueba de Merkle pliega hasta la raíz anclada de la época',
            hash_equals(strtolower((string) $merkleProof['root']), $foldedRoot),
            'época ' . (int) $merkleProof['epoch'] . ', hoja ' . (int) $merkleProof['index']
            . ' de ' . (int) $merkleProof['size'] . ', ' . count((array) $merkleProof['path']) . ' hashes de camino',
        );
    } catch (Throwable $e) {
        check('La prueba de Merkle pliega hasta la raíz anclada de la época', false, $e->getMessage());
    }
}

// --- 7. El diario y su checkpoint firmado -----------------------------------

$entry = field($package, 'journal_entry.entry');
$checkpoint = field($package, 'checkpoint');

if (is_array($entry)) {
    check(
        'La entrada del diario se refiere a este receipt_core',
        hash_equals($declaredHash, strtolower((string) ($entry['data_hash'] ?? ''))),
        'entrada nº ' . (int) ($entry['n'] ?? 0) . ', evento "' . (string) ($entry['event'] ?? '') . '"',
    );
}

if (!is_array($checkpoint)) {
    check(
        'Checkpoint firmado que cubre la entrada (§19.2)',
        false,
        'Ausente: sin checkpoint firmado, el nodo puede reescribir su diario sin contradecirse.',
    );
} else {
    $checkpointBody = [
        'head' => (string) ($checkpoint['head'] ?? ''),
        'n' => (int) ($checkpoint['n'] ?? 0),
        'root' => (string) ($checkpoint['root'] ?? ''),
        'ts' => (string) ($checkpoint['ts'] ?? ''),
    ];

    $checkpointResult = $receiverKey === false ? false : vVerifySignature($receiverKey, 'QSLP1-demo CKPT', vCanonical($checkpointBody), (string) ($checkpoint['signature'] ?? ''));

    check(
        'El checkpoint del diario está firmado por el receptor',
        $checkpointResult,
        $checkpointResult === null ? 'No comprobado: falta la extensión oqsphp' : 'hasta la entrada nº ' . $checkpointBody['n'] . ', fechado ' . $checkpointBody['ts'],
    );

    check(
        'El checkpoint cubre la entrada que registra este mensaje',
        is_array($entry) && (int) $checkpointBody['n'] >= (int) ($entry['n'] ?? PHP_INT_MAX),
        'checkpoint n=' . $checkpointBody['n'] . ', entrada n=' . (int) ($entry['n'] ?? 0),
    );

    $journalProof = field($package, 'journal_proof');

    if (is_array($journalProof) && is_array($entry)) {
        try {
            $journalRoot = vFoldProof(vEntryHash($entry), (array) ($journalProof['path'] ?? []));
            check(
                'La entrada pertenece al diario que el receptor firmó',
                hash_equals(strtolower($checkpointBody['root']), $journalRoot),
                'inclusión de la entrada nº ' . (int) $journalProof['n'] . ' en la raíz del checkpoint',
            );
        } catch (Throwable $e) {
            check('La entrada pertenece al diario que el receptor firmó', false, $e->getMessage());
        }
    } else {
        check(
            'La entrada pertenece al diario que el receptor firmó',
            null,
            'No comprobado: el paquete no trae la prueba de inclusión en el diario.',
        );
    }
}

// --- 8. Consistencia: el diario no se reescribió después --------------------

$consistency = field($package, 'consistency_proof');
$from = is_array($consistency) ? ($consistency['from'] ?? null) : null;
$to = is_array($consistency) ? ($consistency['to'] ?? null) : null;

if (!isset($from['head'], $from['n'], $to['head'], $to['n'])) {
    check(
        'Prueba de consistencia con un checkpoint posterior (§19.3)',
        'ausente',
        'No incluida: sin ella no consta que el nodo no reescribiera su diario después del hecho.',
    );
} elseif ((int) $to['n'] === (int) $from['n']) {
    // Contrastar un checkpoint consigo mismo no demuestra nada, y darlo por
    // bueno con un [ SÍ ] sería engañoso.
    check(
        'Prueba de consistencia con un checkpoint posterior (§19.3)',
        'ausente',
        'El checkpoint que cubre el hecho es el más reciente que el nodo ha publicado: '
        . 'todavía no hay ninguno posterior con el que contrastarlo. Vuelve a exportar el '
        . 'paquete cuando el nodo haya publicado otro.',
    );
} else {
    $head = (string) $from['head'];
    $entries = (array) ($consistency['entries'] ?? []);
    $brokenAt = null;

    foreach ($entries as $next) {
        if (!is_array($next) || !hash_equals($head, (string) ($next['prev'] ?? ''))) {
            $brokenAt = (int) ($next['n'] ?? 0);
            break;
        }

        $head = vEntryHash($next);
    }

    if ($brokenAt !== null) {
        check(
            'El diario encadena desde el checkpoint del hecho hasta el posterior',
            false,
            'El encadenamiento se rompe en la entrada nº ' . $brokenAt . ': el diario fue reescrito.',
        );
    } else {
        $matches = hash_equals((string) $to['head'], $head);

        check(
            'El diario encadena desde el checkpoint del hecho hasta el posterior',
            $matches,
            $matches
                ? count($entries) . ' entradas encadenadas hasta la nº ' . (int) $to['n']
                : 'Las entradas aportadas no llevan a la cabeza que el nodo firmó en el checkpoint '
                    . 'posterior: el diario fue reescrito entre uno y otro.',
        );
    }
}

// --- 9. Sello de tiempo y anclaje -------------------------------------------

$stamp = field($package, 'timestamp');

if (is_array($stamp) && !empty($stamp['present'])) {
    check(
        'Sello de tiempo cualificado sobre la raíz de la época (§11.3)',
        null,
        'Presente, en formato RFC 3161. Este verificador no valida la cadena de la TSA: '
        . 'hazlo con `openssl ts -verify` y el certificado de la autoridad.',
    );
} else {
    check(
        'Sello de tiempo cualificado sobre la raíz de la época (§11.3)',
        'ausente',
        'Ausente: ' . (string) (is_array($stamp) ? ($stamp['reason'] ?? 'sin motivo declarado') : 'el paquete no trae el campo')
        . '. Sin sello cualificado, la fecha la afirma el propio nodo y no es oponible a un tercero.',
    );
}

$anchor = field($package, 'anchor');

if (is_array($anchor) && ($anchor['chain'] ?? '') === 'local') {
    check(
        'Anclaje de la raíz en una cadena (§11.4)',
        'ausente',
        'La raíz está anclada en el diario local del propio nodo, no en una cadena: '
        . 'es un compromiso firmado, pero el nodo es a la vez el que lo custodia.',
    );
} elseif (is_array($anchor)) {
    check(
        'Anclaje de la raíz en una cadena (§11.4)',
        null,
        'El paquete declara cadena "' . (string) ($anchor['chain'] ?? '?') . '". Compruébalo contra ese registro.',
    );
} else {
    check('Anclaje de la raíz en una cadena (§11.4)', false, 'Ausente.');
}

// --- 10. El log de transparencia (§12) ------------------------------------

$logIdentity = field($package, 'log_identity');
$logKey = is_array($logIdentity) ? vB64uDecode((string) ($logIdentity['public_key'] ?? '')) : false;
$logCheckpoint = field($package, 'log_checkpoint');

if ($logKey === false) {
    check(
        'El paquete trae la identidad del log de transparencia (§12)',
        'ausente',
        'Sin ella, lo único que respalda la evidencia es el diario del propio nodo auditado.',
    );
} else {
    if ($expectedLog !== null) {
        check(
            'El log es el indicado en la línea de órdenes',
            hash_equals($expectedLog, (string) ($logIdentity['log_id'] ?? '')),
            'esperado ' . $expectedLog . ', encontrado ' . (string) ($logIdentity['log_id'] ?? ''),
        );
    } else {
        check(
            'El log es el que el paquete dice que es',
            null,
            'No comprobado: la clave del log viaja dentro del propio paquete. Pásala con '
            . '--log-id para atarla a un log que conozcas por otra vía.',
        );
    }

    check(
        'El log tiene identidad distinta de la del nodo central',
        !hash_equals((string) ($logIdentity['log_id'] ?? ''), (string) $core['to']),
        'log ' . (string) ($logIdentity['log_id'] ?? '') . ', nodo receptor ' . (string) $core['to'],
    );

    if (!is_array($logCheckpoint)) {
        check('Checkpoint firmado del log (§12.3)', 'ausente', 'El paquete no lo trae.');
    } else {
        $logCheckpointBody = [
            'acts_root' => strtolower((string) ($logCheckpoint['acts_root'] ?? '')),
            'root' => strtolower((string) ($logCheckpoint['root'] ?? '')),
            'seq' => (int) ($logCheckpoint['seq'] ?? 0),
            'tree_size' => (int) ($logCheckpoint['tree_size'] ?? 0),
            'ts' => (string) ($logCheckpoint['ts'] ?? ''),
        ];
        $logCheckpointResult = vVerifySignature(
            $logKey,
            'QSLP1-demo TLCP',
            vCanonical($logCheckpointBody),
            (string) ($logCheckpoint['signature'] ?? ''),
        );

        check(
            'El checkpoint del log está firmado por el log',
            $logCheckpointResult,
            $logCheckpointResult === null
                ? 'No comprobado: falta la extensión oqsphp'
                : 'checkpoint nº ' . $logCheckpointBody['seq'] . ', con ' . $logCheckpointBody['tree_size']
                    . ' entradas contadas y firmadas',
        );
    }

    $transparency = field($package, 'transparency');

    if (!is_array($transparency) || !isset($transparency['leaf'], $transparency['inclusion'])) {
        check(
            'La raíz de la época consta en el log (§12)',
            'ausente',
            'El paquete no trae la prueba de publicación: el anclaje se queda en el diario del '
            . 'nodo, que es a la vez el auditado.',
        );
    } else {
        $logLeaf = (array) $transparency['leaf'];
        $inclusion = (array) $transparency['inclusion'];
        $inclusionBody = [
            'leaf_hash' => strtolower((string) ($inclusion['leaf_hash'] ?? '')),
            'root' => strtolower((string) ($inclusion['root'] ?? '')),
            'seq' => (int) ($inclusion['seq'] ?? 0),
            'tree_size' => (int) ($inclusion['tree_size'] ?? 0),
        ];

        $inclusionSigned = vVerifySignature(
            $logKey,
            'QSLP1-demo TLSCT',
            vCanonical($inclusionBody),
            (string) ($inclusion['signature'] ?? ''),
        );

        check(
            'La prueba de publicación está firmada por el log',
            $inclusionSigned,
            $inclusionSigned === null ? 'No comprobado: falta la extensión oqsphp'
                : 'entrada nº ' . $inclusionBody['seq'] . ' de ' . $inclusionBody['tree_size'],
        );

        check(
            'El hash de la prueba es el de la hoja aportada',
            hash_equals(vLogLeafHash($logLeaf), $inclusionBody['leaf_hash']),
            'hoja de tipo "' . (string) ($logLeaf['type'] ?? '?') . '"',
        );

        try {
            $logFolded = vFoldProof($inclusionBody['leaf_hash'], (array) ($inclusion['path'] ?? []));
            check(
                'La hoja está incluida en el árbol del log',
                hash_equals($inclusionBody['root'], $logFolded),
                count((array) ($inclusion['path'] ?? [])) . ' hashes de camino',
            );
        } catch (Throwable $e) {
            check('La hoja está incluida en el árbol del log', false, $e->getMessage());
        }

        $publishedRoot = strtolower((string) ($logLeaf['body']['root'] ?? ''));
        $anchoredRoot = strtolower((string) (field($package, 'merkle_proof.root') ?: ''));

        check(
            'La raíz publicada en el log es la misma que la anclada en la época',
            $publishedRoot !== '' && hash_equals($publishedRoot, $anchoredRoot),
            'publicada ' . substr($publishedRoot, 0, 16) . '…, anclada ' . substr($anchoredRoot, 0, 16) . '…',
        );

        $logConsistency = field($package, 'log_consistency');

        if (!is_array($logConsistency) || !isset($logConsistency['proof'])) {
            check(
                'Esa publicación sigue estando en la vista actual del log (§12.3)',
                'ausente',
                'Sin prueba de consistencia, la publicación consta en alguna vista del log, no '
                . 'necesariamente en la que el checkpoint firma hoy.',
            );
        } else {
            $consistent = vConsistencyVerify(
                (int) $logConsistency['from_size'],
                (int) $logConsistency['to_size'],
                (array) $logConsistency['proof'],
                (string) $logConsistency['from_root'],
                (string) $logConsistency['to_root'],
            );

            check(
                'Esa publicación sigue estando en la vista actual del log (§12.3)',
                $consistent,
                $consistent
                    ? 'el árbol de ' . (int) $logConsistency['from_size'] . ' entradas es prefijo del de '
                        . (int) $logConsistency['to_size'] . ', con ' . count((array) $logConsistency['proof'])
                        . ' hashes'
                    : 'la prueba de consistencia no cuadra: el log reescribió su historia',
            );

            check(
                'La raíz consistente es la que el checkpoint firma',
                is_array($logCheckpoint)
                && hash_equals(strtolower((string) $logConsistency['to_root']), strtolower((string) $logCheckpoint['root'])),
                'si no coincidieran, la cadena entre la hoja y la firma se rompería ahí',
            );
        }
    }

    // --- 11. Actos de autoridad y no ocurrencia (§12.2, §19.5) ------------

    $acts = field($package, 'authority_acts');
    $actsRoot = is_array($logCheckpoint) ? strtolower((string) ($logCheckpoint['acts_root'] ?? '')) : '';

    foreach (['sender' => 'emisor', 'receiver' => 'receptor'] as $role => $label) {
        $entry = is_array($acts) ? ($acts[$role] ?? null) : null;

        if (!is_array($entry) || !isset($entry['proof'])) {
            check(
                'Actos de autoridad contra el ' . $label . ' (§12.2)',
                'ausente',
                'El paquete no trae prueba de si existen o no.',
            );

            continue;
        }

        $shown = (array) ($entry['acts'] ?? []);
        $value = $entry['proof']['value'] ?? null;
        $valueMatches = empty($shown)
            ? $value === null
            : (is_string($value) && hash_equals(vActsValue($shown), strtolower($value)));

        $folded = vSparseVerify($entry['proof'], $actsRoot);

        if (empty($shown)) {
            check(
                'No consta NINGÚN acto de autoridad contra el ' . $label . ' (§19.5)',
                $valueMatches && $folded,
                $valueMatches && $folded
                    ? 'prueba de no inclusión contra la raíz de actos que el log firma: esto no es '
                        . 'un «no lo sé», es un «no existe»'
                    : 'la prueba de no inclusión no cuadra con la raíz firmada',
            );
        } else {
            check(
                'Los actos contra el ' . $label . ' son exactamente ' . count($shown) . ' (§12.2)',
                $valueMatches && $folded,
                $valueMatches && $folded
                    ? 'y no hay más en esta vista del log: la lista completa cuadra con la raíz firmada'
                    : 'la lista que se enseña no cuadra con la raíz firmada: falta o sobra algún acto',
            );
        }
    }
}

// --- 12. Revocación y certificados ------------------------------------------

check(
    'Estado de revocación a la fecha del hecho (§19.3)',
    'ausente',
    'No incluido: ' . (string) (field($package, 'revocation_absent') ?: 'el paquete no trae el campo'),
);

report($checks, $package);

/**
 * @param array<int, array{nombre: string, resultado: bool|null, detalle: string}> $checks
 * @param array $package
 *
 * @return void
 */
function report(array $checks, array $package)
{
    $passed = 0;
    $failed = 0;
    $gaps = 0;
    $unchecked = 0;

    fwrite(STDOUT, "\n");
    fwrite(STDOUT, "INFORME DE VERIFICACIÓN DE EVIDENCIA — QSLP/1 §19.4\n");
    fwrite(STDOUT, str_repeat('=', 72) . "\n\n");

    $claim = field($package, 'claim');

    if (is_string($claim) && $claim !== '') {
        fwrite(STDOUT, "Lo que se afirma:\n  " . wordwrap($claim, 68, "\n  ") . "\n\n");
    }

    foreach ($checks as $oneCheck) {
        if ($oneCheck['resultado'] === true) {
            $mark = '[ SÍ ]';
            $passed++;
        } elseif ($oneCheck['resultado'] === false) {
            $mark = '[ NO ]';
            $failed++;
        } elseif ($oneCheck['resultado'] === 'ausente') {
            $mark = '[ !! ]';
            $gaps++;
        } else {
            $mark = '[ -- ]';
            $unchecked++;
        }

        fwrite(STDOUT, $mark . ' ' . $oneCheck['nombre'] . "\n");

        if ($oneCheck['detalle'] !== '') {
            fwrite(STDOUT, '       ' . wordwrap($oneCheck['detalle'], 64, "\n       ") . "\n");
        }
    }

    $provenance = field($package, 'crypto_provenance');

    if (is_array($provenance)) {
        fwrite(STDOUT, "\nProcedencia criptográfica declarada (§19.8):\n");
        fwrite(STDOUT, '  liboqs ' . (string) ($provenance['liboqs'] ?? '?')
            . ', PHP ' . (string) ($provenance['php'] ?? '?')
            . ', suite ' . (string) ($provenance['suite'] ?? '?') . "\n");
    }

    fwrite(STDOUT, "\n" . str_repeat('-', 72) . "\n");
    fwrite(STDOUT, sprintf(
        "Resultado: %d correctas, %d fallidas, %d carencias del paquete, %d no comprobables.\n",
        $passed,
        $failed,
        $gaps,
        $unchecked,
    ));

    if ($failed === 0) {
        fwrite(STDOUT, "\nTodo lo que se puede comprobar aquí, cuadra: las firmas verifican y las\n"
            . "pruebas pliegan hasta donde el nodo se comprometió.\n");
    } else {
        fwrite(STDOUT, "\nHay comprobaciones FALLIDAS. Este paquete NO sostiene lo que afirma.\n");
    }

    if ($gaps > 0) {
        fwrite(STDOUT, "\nLas " . $gaps . " líneas marcadas [ !! ] son carencias de este paquete, no\n"
            . "fallos de verificación: lo que falta ahí es lo que un tercero echaría en falta.\n"
            . "Léelas antes de presentar esto en ningún sitio.\n");
    }

    if ($unchecked > 0) {
        fwrite(STDOUT, "\nLas marcadas [ -- ] no se han comprobado: este programa no puede, y dice\n"
            . "por qué en cada una.\n");
    }

    fwrite(STDOUT, "\nEn ningún caso esto acredita que el contenido del mensaje sea verdadero, ni\n"
        . "que quien firmó estuviera autorizado a hacerlo: solo que esa clave firmó eso\n"
        . "y que el receptor lo acusó (§19.12).\n\n");

    exit($failed === 0 ? 0 : 1);
}
