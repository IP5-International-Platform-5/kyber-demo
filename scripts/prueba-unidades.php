<?php

/**
 * Comprobaciones de las piezas del paso 5 que se pueden probar sin HTTP.
 *
 *   php scripts/prueba-unidades.php
 *
 * Son las propiedades de las que depende todo lo demás: canonicalización
 * estable, un árbol de Merkle que no admite dos listas con la misma raíz,
 * firmas que no se pueden mover de un contexto a otro, un diario cuyo
 * encadenamiento delata la reescritura y una ventana anti-replay que no se
 * puede envenenar. Si algo de esto falla, la prueba de extremo a extremo
 * seguiría pasando y la evidencia no valdría nada.
 *
 * Todo lo que escribe va a un directorio temporal: las constantes de rutas se
 * fijan antes de cargar las bibliotecas, así que el diario real no se toca.
 * Sin la extensión oqsphp (fuera del contenedor) las comprobaciones de firma
 * se marcan como omitidas en lugar de hacer fallar el conjunto.
 */

$temp = sys_get_temp_dir() . '/qslp-prueba-' . bin2hex(random_bytes(6));

define('IDENTITY_DIR', $temp . '/identities');
define('JOURNAL_DIR', $temp . '/journal');
define('RECEIPT_DIR', $temp . '/journal/receipts');
define('EPOCH_DIR', $temp . '/journal/epochs');
define('EPOCH_SECONDS', 60);
// Un checkpoint cada tres entradas, para ver el mecanismo funcionar sin
// escribir mil. En producción son los valores de la §19.2.
define('CHECKPOINT_EVERY', 3);
define('CHECKPOINT_SECONDS', 3600);

require_once __DIR__ . '/../libs/canonical.php';
require_once __DIR__ . '/../libs/merkle.php';
require_once __DIR__ . '/../libs/identity.php';
require_once __DIR__ . '/../libs/receipt.php';
require_once __DIR__ . '/../libs/journal.php';
require_once __DIR__ . '/../libs/epoch.php';

/**
 * Contadores del conjunto. En una clase y no en variables globales para que el
 * análisis estático pueda razonar sobre ellos: con `global` da por constante lo
 * que las funciones cambian, y avisa de comparaciones "siempre ciertas".
 */
final class Tally
{
    /** @var int */
    public static $failures = 0;

    /** @var int */
    public static $skipped = 0;
}

/**
 * @param string $name
 * @param bool $condition
 * @param string $detail
 *
 * @return void
 */
function ok($name, $condition, $detail = '')
{
    if ($condition) {
        echo "ok    $name\n";

        return;
    }

    echo "FALLA $name" . ($detail === '' ? '' : " — $detail") . "\n";
    Tally::$failures++;
}

/**
 * @param string $name
 * @param string $reason
 *
 * @return void
 */
function skip($name, $reason)
{
    Tally::$skipped++;
    echo "omite $name — $reason\n";
}

echo "— Canonicalización (§6.1)\n";

ok('JCS ordena las claves', canonicalJson(['b' => 1, 'a' => 2]) === '{"a":2,"b":1}');
ok('JCS ordena en profundidad', canonicalJson(['z' => ['y' => 1, 'x' => [3, 1]]]) === '{"z":{"x":[3,1],"y":1}}');
ok('JCS conserva el orden de las listas', canonicalJson([3, 1, 2]) === '[3,1,2]');
ok('JCS no escapa las barras', canonicalJson(['u' => 'a/b']) === '{"u":"a/b"}');

try {
    canonicalJson(['a' => 1.5]);
    ok('JCS rechaza los flotantes en lugar de inventarles formato', false);
} catch (InvalidArgumentException $e) {
    ok('JCS rechaza los flotantes en lugar de inventarles formato', true);
}

ok('base64url ida y vuelta con bytes crudos', b64uDecode(b64uEncode("\x00\xff\x10binario")) === "\x00\xff\x10binario");
ok('base64url sin relleno', strpos(b64uEncode('abcde'), '=') === false);
ok('base64url estricto rechaza el relleno', b64uDecode('YWJj=') === false);
ok('base64url estricto rechaza el alfabeto estándar', b64uDecode('a+b/c') === false);

echo "\n— Identificador de nodo (§5.1)\n";

$key = random_bytes(1952);
ok('node_id con el prefijo y la longitud de la especificación', preg_match('/^ip5:[A-Z2-7]{26}$/', nodeId($key)) === 1, nodeId($key));
ok('node_id determinista', nodeId($key) === nodeId($key));
ok('node_id distinto para otra clave', nodeId($key) !== nodeId(random_bytes(1952)));
ok('base32 coincide con el RFC 4648 ("foobar")', base32NoPad('foobar') === 'MZXW6YTBOI');

echo "\n— Reloj (§6.2)\n";

ok('rfc3339 en UTC', preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', rfc3339()) === 1);
ok('parseRfc3339 ida y vuelta', parseRfc3339(rfc3339(1760000000)) === 1760000000);
ok('parseRfc3339 rechaza otro formato', parseRfc3339('2026-10-11 20:00:00') === null);
ok('±120 s: acepta 100 s de desvío', clockSkewAcceptable(rfc3339(time() - 100)));
ok('±120 s: rechaza 200 s en el pasado', !clockSkewAcceptable(rfc3339(time() - 200)));
ok('±120 s: rechaza 300 s en el futuro', !clockSkewAcceptable(rfc3339(time() + 300)));

echo "\n— Árbol de Merkle (§11.4)\n";

$leaves = [];
for ($i = 0; $i < 7; $i++) {
    $leaves[] = hash('sha3-256', "hoja$i");
}

ok('la raíz depende del orden', merkleRoot($leaves) !== merkleRoot(array_reverse($leaves)));

$verified = 0;
$rejected = 0;
for ($i = 0; $i < 7; $i++) {
    $path = merkleProof($leaves, $i);
    $verified += merkleVerify($leaves[$i], $path, merkleRoot($leaves)) ? 1 : 0;
    $rejected += merkleVerify(hash('sha3-256', 'ajena'), $path, merkleRoot($leaves)) ? 0 : 1;
}

ok('las siete pruebas de inclusión verifican', $verified === 7, "$verified de 7");
ok('ninguna prueba vale para una hoja ajena', $rejected === 7, "$rejected de 7");

$path = merkleProof($leaves, 3);
$path[0]['side'] = $path[0]['side'] === 'left' ? 'right' : 'left';
ok('cambiar el lado de un paso invalida la prueba', !merkleVerify($leaves[3], $path, merkleRoot($leaves)));

$twoLeaves = merkleRoot([$leaves[0], $leaves[1]]);
ok('un nodo interno no se puede presentar como hoja', merkleRoot([$twoLeaves]) !== $twoLeaves);
ok(
    'el impar se promueve, no se duplica: [a,b,c] y [a,b,c,c] no colisionan',
    merkleRoot(array_slice($leaves, 0, 3)) !== merkleRoot([$leaves[0], $leaves[1], $leaves[2], $leaves[2]]),
);

try {
    merkleRoot([]);
    ok('una época sin hojas no tiene raíz', false);
} catch (InvalidArgumentException $e) {
    ok('una época sin hojas no tiene raíz', true);
}

echo "\n— Ventana anti-replay (§8.2)\n";

$window = [];
$first = replayAccept($window, 0);
ok('acepta el primer número de secuencia', $first['ok']);
$window = $first['window'];

$repeated = replayAccept($window, 0);
ok('rechaza el mismo número dos veces', !$repeated['ok'] && $repeated['error'] === 'E_REPLAY');

$window = replayAccept($window, 5)['window'];
$window = replayAccept($window, 3)['window'];
ok('acepta desordenado dentro de la ventana', replayAccept($window, 4)['ok']);

$window = replayAccept($window, 200)['window'];
$old = replayAccept($window, 100);
ok('rechaza lo que queda por detrás de la ventana de 64', !$old['ok'] && $old['error'] === 'E_REPLAY');
ok('acepta dentro de la ventana tras un salto', replayAccept($window, 150)['ok']);
ok('la ventana se poda y no crece sin límite', count($window['seen']) <= 65, (string) count($window['seen']));

echo "\n— receipt_core (§11.1)\n";

$core = receiptCore('abc', 0, 'ip5:A', 'ip5:B', rfc3339(), hash('sha3-256', 'hola'), str_repeat('ab', 32));
ok('receipt_core bien formado se acepta', receiptCoreWellFormed($core));

$missingField = $core;
unset($missingField['th']);
ok('falta un campo: se rechaza', !receiptCoreWellFormed($missingField));

$extraField = $core + ['extra' => 1];
ok('campo de más: se rechaza (lo cubriría la firma y no las comprobaciones)', !receiptCoreWellFormed($extraField));

$badHash = $core;
$badHash['payload_hash'] = 'no-es-un-hash';
ok('payload_hash mal formado: se rechaza', !receiptCoreWellFormed($badHash));

$coreHash = receiptCoreHash($core);
ok('el hash del núcleo es estable', $coreHash === receiptCoreHash($core));
ok('cambiar un campo cambia el hash', $coreHash !== receiptCoreHash(receiptCore('abc', 1, 'ip5:A', 'ip5:B', $core['ts'], $core['payload_hash'], $core['th'])));

echo "\n— Firmas (§11.1, §11.2, §19.2)\n";

if (!class_exists('OQS_SIGNATURE')) {
    skip('todas las comprobaciones de firma', 'falta la extensión oqsphp (ejecútalo dentro del contenedor)');
} else {
    $sender = loadOrCreateIdentity('app');
    $receiver = loadOrCreateIdentity('srv');

    ok('la identidad se crea al primer uso y se reutiliza', loadOrCreateIdentity('app')['public'] === $sender['public']);

    $signature = signReceiptCore($sender['private'], $core);
    ok('la firma del emisor verifica', verifyReceiptCore($sender['public'], $core, $signature));
    ok('no verifica con la clave del receptor', !verifyReceiptCore($receiver['public'], $core, $signature));

    $otherCore = $core;
    $otherCore['seq'] = 1;
    ok('no verifica sobre un núcleo distinto', !verifyReceiptCore($sender['public'], $otherCore, $signature));

    $forwarded = $core;
    $forwarded['to'] = 'ip5:C';
    ok('reenvío a un tercero: la firma no cubre el nuevo destinatario', !verifyReceiptCore($sender['public'], $forwarded, $signature));

    // Separación de dominios: la misma clave firma transcripts, núcleos, acuses
    // y checkpoints, y una firma de un contexto no debe valer en otro.
    $crossDomain = b64uEncode(signDomain($sender['private'], 'QSLP1-demo RCPT', canonicalJson($core)));
    ok('una firma hecha con otra etiqueta de dominio no vale', !verifyReceiptCore($sender['public'], $core, $crossDomain));

    $receipt = buildReceipt($receiver['private'], $coreHash, nodeId($receiver['public']));
    ok('el acuse de recibo verifica', verifyReceipt($receipt, $receiver['public'], $coreHash));
    ok('el acuse no verifica contra otro núcleo', !verifyReceipt($receipt, $receiver['public'], hash('sha3-256', 'otro')));
    ok('el acuse no verifica con la clave del emisor', !verifyReceipt($receipt, $sender['public'], $coreHash));

    $tampered = $receipt;
    $tampered['ts'] = rfc3339(time() + 3600);
    ok('cambiar la fecha del acuse lo invalida', !verifyReceipt($tampered, $receiver['public'], $coreHash));

    echo "\n— Sobre firmado y cifrado (§11.1)\n";

    $envelope = buildMessageEnvelope('hola mundo', $core, $sender['private']);
    $opened = openMessageEnvelope($envelope['envelope']);
    ok('el sobre se abre y devuelve el mensaje', $opened['message'] === 'hola mundo');
    ok('el sobre conserva el núcleo', receiptCoreHash($opened['core']) === $coreHash);
    ok('la firma del sobre verifica', verifyReceiptCore($sender['public'], $opened['core'], $opened['signature']));

    $binaryEnvelope = buildMessageEnvelope("\x00\xffbytes crudos", $core, $sender['private']);
    ok('un mensaje que no es UTF-8 válido sobrevive al sobre', openMessageEnvelope($binaryEnvelope['envelope'])['message'] === "\x00\xffbytes crudos");

    $broken = json_decode($envelope['envelope'], true);
    $broken['m'] = b64uEncode('otro mensaje');
    ok('cambiar el mensaje y dejar la firma: no verifica', !verifyReceiptCore($sender['public'], $broken['core'], $broken['sig'])
        || !hash_equals($broken['core']['payload_hash'], hash('sha3-256', 'otro mensaje')));

    try {
        openMessageEnvelope('{"type":"MSG"}');
        ok('un sobre incompleto se rechaza', false);
    } catch (RuntimeException $e) {
        ok('un sobre incompleto se rechaza', true);
    }

    echo "\n— Diario y checkpoints (§19.2)\n";

    $firstEntry = journalAppend('srv', 'prueba', hash('sha3-256', 'uno'));
    // El valor se escribe aquí entero en lugar de usar la constante: así se
    // comprueba lo que el diario pone de verdad y no que dos símbolos coinciden.
    ok('la primera entrada encadena al génesis', $firstEntry['prev'] === str_repeat('0', 64) && (int) $firstEntry['n'] === 1);

    journalAppend('srv', 'prueba', hash('sha3-256', 'dos'));
    $thirdEntry = journalAppend('srv', 'prueba', hash('sha3-256', 'tres'));
    ok('la tercera entrada encadena a la segunda', (int) $thirdEntry['n'] === 3);

    $entries = journalEntries('srv');
    ok('el encadenamiento verifica', journalVerifyChain($entries)['ok']);

    $checkpoint = journalCheckpoint('srv');
    ok('el checkpoint se firma y se puede verificar', journalVerifyCheckpoint($checkpoint, $receiver['public']));
    ok('el checkpoint no verifica con otra identidad', !journalVerifyCheckpoint($checkpoint, $sender['public']));

    $forged = $checkpoint;
    $forged['n'] = 99;
    ok('cambiar el checkpoint lo invalida', !journalVerifyCheckpoint($forged, $receiver['public']));

    $proof = journalInclusionProof('srv', 2, (int) $checkpoint['n']);
    ok('la entrada nº 2 se prueba contra la raíz del checkpoint', merkleVerify(journalEntryHash($entries[1]), $proof['path'], $checkpoint['root']));

    // Reescritura: cambiar una entrada ya escrita rompe el encadenamiento, y el
    // checkpoint firmado antes contradice la versión nueva. Es lo único que un
    // diario local puede ofrecer, y es lo que un auditor necesita.
    $rewritten = $entries;
    $rewritten[1]['data_hash'] = hash('sha3-256', 'historia reescrita');
    $chainCheck = journalVerifyChain($rewritten);
    ok('reescribir una entrada rompe el encadenamiento', !$chainCheck['ok'] && $chainCheck['broken_at'] === 3);
    ok('la reescritura contradice el checkpoint ya firmado', journalRoot($rewritten) !== $checkpoint['root']);

    journalAppend('srv', 'prueba', hash('sha3-256', 'cuatro'));
    $later = journalCheckpoint('srv');
    $consistency = journalConsistencyProof('srv', $checkpoint, $later);
    $head = $checkpoint['head'];
    foreach ($consistency['entries'] as $entry) {
        $head = hash_equals($head, (string) $entry['prev']) ? journalEntryHash($entry) : 'roto';
    }
    ok('la prueba de consistencia encadena de un checkpoint al siguiente', $head === $later['head']);

    echo "\n— Épocas y anclaje (§11.4)\n";

    $epoch = epochOf();
    $index = epochAddLeaf($epoch, $coreHash);
    ok('la primera hoja de la época ocupa la posición 0', $index === 0);
    ok('añadir la misma hoja no la duplica', epochAddLeaf($epoch, $coreHash) === 0);

    $secondLeaf = hash('sha3-256', 'otro recibo');
    epochAddLeaf($epoch, $secondLeaf);
    ok('la segunda hoja ocupa la posición 1', count(epochLeaves($epoch)) === 2);

    $record = epochClose($epoch);
    ok('cerrar la época produce raíz y tamaño', $record['root'] === merkleRoot([$coreHash, $secondLeaf]) && $record['size'] === 2);
    ok('la época cerrada queda anclada', epochIsClosed($epoch));
    ok('el anclaje declara que es local y no una cadena', $record['anchor']['chain'] === 'local');
    ok('cerrar la época fuerza un checkpoint firmado', journalVerifyCheckpoint($record['checkpoint'], $receiver['public']));
    ok('el sello de tiempo se declara ausente con su motivo', $record['timestamp']['present'] === false && isset($record['timestamp']['reason']));
    ok('cerrar dos veces devuelve el mismo registro', epochClose($epoch)['root'] === $record['root']);

    try {
        epochAddLeaf($epoch, hash('sha3-256', 'tarde'));
        ok('una época anclada ya no admite hojas', false);
    } catch (RuntimeException $e) {
        ok('una época anclada ya no admite hojas', true);
    }

    $epochProof = epochProofFor($epoch, $coreHash);
    ok('la prueba de inclusión de la época verifica', merkleVerify($coreHash, $epochProof['path'], $record['root']));
    ok('un recibo ajeno no tiene prueba en esta época', epochProofFor($epoch, hash('sha3-256', 'ajeno')) === null);

    echo "\n— Registros de recibo\n";

    receiptRecordStore('srv', ['core' => $core, 'core_hash' => $coreHash, 'sender_signature' => $signature]);
    ok('el registro se guarda y se recupera', receiptRecordLoad('srv', $coreHash)['core_hash'] === $coreHash);
    ok('cada rol guarda su propia copia', receiptRecordLoad('app', $coreHash) === null);

    $contents = (string) file_get_contents(RECEIPT_DIR . '/srv/' . $coreHash . '.json');
    ok('el registro no contiene texto en claro ni material de clave', strpos($contents, 'hola mundo') === false
        && strpos($contents, b64uEncode($receiver['private'])) === false);
}

// Limpieza: nada de esto debe quedarse en la máquina. Sin exec(), que no está
// disponible en todas las instalaciones.
removeTree($temp);

/**
 * @param string $path
 *
 * @return void
 */
function removeTree($path)
{
    if (!is_dir($path)) {
        @unlink($path);

        return;
    }

    foreach (array_diff((array) scandir($path), ['.', '..']) as $entry) {
        removeTree($path . '/' . $entry);
    }

    @rmdir($path);
}

echo "\n" . str_repeat('-', 60) . "\n";
if (Tally::$failures === 0) {
    echo 'Todo correcto' . (Tally::$skipped > 0
        ? (Tally::$skipped === 1
            ? ", con 1 comprobación omitida.\n"
            : ', con ' . Tally::$skipped . " comprobaciones omitidas.\n")
        : ".\n");
} else {
    echo Tally::$failures === 1 ? "1 comprobación fallida.\n" : Tally::$failures . " comprobaciones fallidas.\n";
}

exit(Tally::$failures === 0 ? 0 : 1);
