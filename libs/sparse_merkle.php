<?php

/**
 * Árbol de Merkle disperso, para pruebas de NO inclusión (§19.5).
 *
 * Un árbol de Merkle normal demuestra que algo está. Esto demuestra que algo
 * **no** está, que es la pregunta que de verdad hace un auditor: no solo
 * «¿hizo esto?», sino «¿hizo algo más que no me está enseñando?» y «¿es cierto
 * que nunca hizo X?».
 *
 * Con esto, el nodo central acusado de censura puede demostrar que no bloqueó
 * a nadie, y el nodo ligero acusado puede demostrar que no recibió una orden.
 * La §19.5 lo llama simetría probatoria, y es lo que casi ningún sistema tiene.
 *
 * Cómo: el árbol tiene una hoja por cada clave posible de 256 bits —2^256
 * hojas, casi todas vacías—, así que la posición de un sujeto está fijada por
 * su clave y nadie puede «moverlo» a otro sitio. Los subárboles vacíos tienen
 * un hash conocido por nivel, que quien verifica calcula por su cuenta, de modo
 * que una prueba solo necesita los hermanos que no están vacíos. Las de aquí
 * viajan con un mapa de bits que dice en qué niveles hay hermano de verdad.
 */

require_once __DIR__ . '/canonical.php';
require_once __DIR__ . '/merkle.php';

if (!defined('SMT_DEPTH')) {
    define('SMT_DEPTH', 256);
}

/**
 * Clave de un sujeto dentro del árbol. Al derivarla de un hash, nadie elige su
 * posición ni puede colocarse al lado de otro a propósito.
 *
 * @param string $subject Normalmente un node_id (§5.1)
 *
 * @return string 64 caracteres hexadecimales
 */
function smtKey($subject)
{
    return hash('sha3-256', 'QSLP1-demo SMT key' . $subject);
}

/**
 * Hashes de los subárboles vacíos, por altura: el 0 es la hoja vacía y el 256,
 * el árbol entero vacío. Se calculan una vez.
 *
 * @return string[] Bytes crudos, indexados por altura
 */
function smtDefaults()
{
    static $defaults = null;

    if ($defaults === null) {
        $defaults = [hash('sha3-256', "\x10" . 'QSLP1-demo SMT empty', true)];

        for ($height = 1; $height <= SMT_DEPTH; $height++) {
            $defaults[$height] = smtNode($defaults[$height - 1], $defaults[$height - 1]);
        }
    }

    return $defaults;
}

/**
 * @param string $left Bytes crudos
 * @param string $right Bytes crudos
 *
 * @return string Bytes crudos
 */
function smtNode($left, $right)
{
    return hash('sha3-256', "\x11" . $left . $right, true);
}

/**
 * La hoja cubre la clave además del valor: sin eso, el valor de un sujeto se
 * podría presentar como el de otro.
 *
 * @param string $keyHex
 * @param string $valueHex
 *
 * @return string Bytes crudos
 */
function smtLeaf($keyHex, $valueHex)
{
    return hash('sha3-256', "\x12" . merkleRawFromHex($keyHex) . merkleRawFromHex($valueHex), true);
}

/**
 * Bit número $index de una clave, contando desde el más significativo.
 *
 * @param string $keyHex
 * @param int $index
 *
 * @return int 0 o 1
 */
function smtBit($keyHex, $index)
{
    $byte = ord(merkleRawFromHex($keyHex)[intdiv($index, 8)]);

    return ($byte >> (7 - ($index % 8))) & 1;
}

/**
 * Raíz del árbol con las entradas dadas.
 *
 * @param array<string, string> $entries clave hexadecimal => valor hexadecimal
 *
 * @return string 64 caracteres hexadecimales
 */
function smtRoot(array $entries)
{
    return bin2hex(smtBuild(0, array_keys($entries), $entries));
}

/**
 * Construye el subárbol que cuelga del nivel $depth para las claves dadas.
 * Las ramas sin claves no se recorren: valen su hash por defecto.
 *
 * @param int $depth
 * @param string[] $keys
 * @param array<string, string> $entries
 *
 * @return string Bytes crudos
 */
function smtBuild($depth, array $keys, array $entries)
{
    $defaults = smtDefaults();

    if (empty($keys)) {
        return $defaults[SMT_DEPTH - $depth];
    }

    if ($depth === SMT_DEPTH) {
        $key = $keys[0];

        return smtLeaf($key, (string) $entries[$key]);
    }

    $left = [];
    $right = [];

    foreach ($keys as $key) {
        if (smtBit($key, $depth) === 0) {
            $left[] = $key;
        } else {
            $right[] = $key;
        }
    }

    return smtNode(
        smtBuild($depth + 1, $left, $entries),
        smtBuild($depth + 1, $right, $entries),
    );
}

/**
 * Prueba de inclusión o de no inclusión de una clave.
 *
 * Es la misma prueba en los dos casos: lo que cambia es si la hoja lleva valor
 * o está vacía. Esa simetría es justamente lo que permite demostrar una
 * ausencia.
 *
 * @param string $keyHex
 * @param array<string, string> $entries
 *
 * @return array<string, mixed>
 */
function smtProof($keyHex, array $entries)
{
    $keyHex = strtolower($keyHex);
    $defaults = smtDefaults();
    $keys = array_keys($entries);
    $siblings = [];
    $bitmap = str_repeat('0', SMT_DEPTH);

    for ($depth = 0; $depth < SMT_DEPTH; $depth++) {
        $bit = smtBit($keyHex, $depth);
        $siblingKeys = [];

        foreach ($keys as $candidate) {
            if (smtBit($candidate, $depth) !== $bit) {
                $siblingKeys[] = $candidate;
            }
        }

        $sibling = smtBuild($depth + 1, $siblingKeys, $entries);

        if (!hash_equals($defaults[SMT_DEPTH - $depth - 1], $sibling)) {
            // Solo viajan los hermanos que no están vacíos; los demás los
            // calcula quien verifica.
            $bitmap[$depth] = '1';
            $siblings[] = bin2hex($sibling);
        }

        // Nos quedamos con las claves de nuestro lado para el nivel siguiente.
        $keys = array_values(array_filter($keys, function ($candidate) use ($depth, $bit) {
            return smtBit($candidate, $depth) === $bit;
        }));
    }

    return [
        'key' => $keyHex,
        'value' => array_key_exists($keyHex, $entries) ? (string) $entries[$keyHex] : null,
        'present' => array_key_exists($keyHex, $entries),
        'bitmap' => bin2hex(smtBitmapToBytes($bitmap)),
        'siblings' => $siblings,
        'root' => smtRoot($entries),
        'depth' => SMT_DEPTH,
    ];
}

/**
 * @param string $bitmap Cadena de 256 caracteres '0' y '1'
 *
 * @return string 32 bytes crudos
 */
function smtBitmapToBytes($bitmap)
{
    $bytes = '';

    foreach (str_split($bitmap, 8) as $chunk) {
        $bytes .= chr((int) bindec($chunk));
    }

    return $bytes;
}

/**
 * @param string $bitmapHex
 *
 * @return string Cadena de 256 caracteres '0' y '1'
 */
function smtBitmapFromHex($bitmapHex)
{
    $raw = merkleRawFromHex(strtolower($bitmapHex));
    $bits = '';

    for ($i = 0; $i < strlen($raw); $i++) {
        $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
    }

    return $bits;
}

/**
 * Comprueba una prueba del árbol disperso contra una raíz firmada.
 *
 * @param array $proof
 * @param string $rootHex Raíz de un checkpoint firmado por el log
 *
 * @return bool
 */
function smtVerify($proof, $rootHex)
{
    if (!is_array($proof) || !isset($proof['key'], $proof['bitmap'], $proof['siblings'])) {
        return false;
    }

    try {
        $defaults = smtDefaults();
        $keyHex = strtolower((string) $proof['key']);
        $bits = smtBitmapFromHex((string) $proof['bitmap']);
        $siblings = array_values((array) $proof['siblings']);
        $value = $proof['value'] ?? null;

        $current = ($value === null)
            ? $defaults[0]
            : smtLeaf($keyHex, (string) $value);

        $next = count($siblings) - 1;

        for ($depth = SMT_DEPTH - 1; $depth >= 0; $depth--) {
            if ($bits[$depth] === '1') {
                if ($next < 0) {
                    return false;
                }
                $sibling = merkleRawFromHex(strtolower((string) $siblings[$next]));
                $next--;
            } else {
                $sibling = $defaults[SMT_DEPTH - $depth - 1];
            }

            $current = smtBit($keyHex, $depth) === 0
                ? smtNode($current, $sibling)
                : smtNode($sibling, $current);
        }

        if ($next !== -1) {
            // Sobran hermanos: una prueba con material de más no es una prueba.
            return false;
        }

        return hash_equals(strtolower((string) $rootHex), bin2hex($current));
    } catch (Throwable $e) {
        return false;
    }
}
