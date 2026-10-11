<?php

/**
 * Árboles de Merkle con la forma que fijó el RFC 6962 para los registros de
 * transparencia.
 *
 * La §11.4 ancla una raíz por época y nada más: 32 bytes representan todos los
 * mensajes de ese minuto, sin contenido, sin metadatos y sin identificadores
 * personales en la cadena. Cualquiera puede luego demostrar que su propio
 * mensaje estaba incluido con log2(n) hashes, sin ver los de los demás.
 *
 * Dos detalles que no son decoración:
 *
 * - Las hojas y los nodos internos se resumen con prefijos distintos (0x00,
 *   0x01). Sin esa separación, un nodo interno se puede presentar como hoja y
 *   un atacante construye un segundo árbol con la misma raíz.
 * - Los niveles impares promueven el último nodo en lugar de duplicarlo.
 *   Duplicar es lo que hace Bitcoin, y provoca que dos listas de hojas
 *   distintas colisionen en una misma raíz, que es justo lo que una prueba de
 *   inclusión no debe permitir.
 */

require_once __DIR__ . '/canonical.php';

/**
 * @param string $leafHex Hash de un receipt_core, 64 caracteres hexadecimales
 *
 * @return string Hash de hoja, 32 bytes crudos
 */
function merkleLeaf($leafHex)
{
    $raw = merkleRawFromHex($leafHex);

    return hash('sha3-256', "\x00" . $raw, true);
}

/**
 * @param string $left Hash de nodo crudo
 * @param string $right Hash de nodo crudo
 *
 * @return string Hash de nodo, 32 bytes crudos
 */
function merkleNode($left, $right)
{
    return hash('sha3-256', "\x01" . $left . $right, true);
}

/**
 * @param string $hex
 *
 * @throws InvalidArgumentException Si la entrada no es un resumen de 32 bytes en hexadecimal
 *
 * @return string Bytes crudos
 */
function merkleRawFromHex($hex)
{
    if (!is_string($hex) || preg_match('/^[0-9a-f]{64}$/', $hex) !== 1) {
        throw new InvalidArgumentException('Una hoja de Merkle son 64 caracteres hexadecimales en minúscula');
    }

    $raw = hex2bin($hex);

    if ($raw === false) {
        throw new InvalidArgumentException('Una hoja de Merkle son 64 caracteres hexadecimales en minúscula');
    }

    return $raw;
}

/**
 * Mayor potencia de dos estrictamente menor que $n: el punto de corte del RFC 6962.
 *
 * @param int $n
 *
 * @return int
 */
function merkleSplit($n)
{
    $k = 1;
    while ($k * 2 < $n) {
        $k *= 2;
    }

    return $k;
}

/**
 * @param string[] $leavesHex Hashes de recibo, en el orden en que se procesaron
 *
 * @throws InvalidArgumentException Con la lista vacía: una época sin recibos no
 *                                  tiene raíz, y anclar un cero sería mentir
 *
 * @return string Raíz en 64 caracteres hexadecimales
 */
function merkleRoot(array $leavesHex)
{
    return bin2hex(merkleRootRaw(array_values($leavesHex)));
}

/**
 * @param string[] $leavesHex
 *
 * @return string Raíz cruda
 */
function merkleRootRaw(array $leavesHex)
{
    $n = count($leavesHex);

    if ($n === 0) {
        throw new InvalidArgumentException('Un conjunto de hojas vacío no tiene raíz de Merkle');
    }

    if ($n === 1) {
        return merkleLeaf($leavesHex[0]);
    }

    $k = merkleSplit($n);

    return merkleNode(
        merkleRootRaw(array_slice($leavesHex, 0, $k)),
        merkleRootRaw(array_slice($leavesHex, $k)),
    );
}

/**
 * Prueba de inclusión de una hoja.
 *
 * Cada paso lleva de qué lado está el hermano, así que quien verifica puede
 * plegar el camino sin que le digan el tamaño del árbol, y no se le puede
 * engañar para que lo pliegue en el otro orden.
 *
 * @param string[] $leavesHex
 * @param int $index Posición de la hoja que se quiere probar
 *
 * @throws InvalidArgumentException Si el índice queda fuera del árbol
 *
 * @return array<int, array{side: string, hash: string}>
 */
function merkleProof(array $leavesHex, $index)
{
    $leavesHex = array_values($leavesHex);
    $n = count($leavesHex);

    if (!is_int($index) || $index < 0 || $index >= $n) {
        throw new InvalidArgumentException('El índice de hoja queda fuera del árbol');
    }

    if ($n === 1) {
        return [];
    }

    $k = merkleSplit($n);

    if ($index < $k) {
        $path = merkleProof(array_slice($leavesHex, 0, $k), $index);
        $path[] = ['side' => 'right', 'hash' => bin2hex(merkleRootRaw(array_slice($leavesHex, $k)))];

        return $path;
    }

    $path = merkleProof(array_slice($leavesHex, $k), $index - $k);
    $path[] = ['side' => 'left', 'hash' => bin2hex(merkleRootRaw(array_slice($leavesHex, 0, $k)))];

    return $path;
}

/**
 * Pliega una prueba de inclusión y la compara con la raíz anclada.
 *
 * @param string $leafHex Hash del receipt_core que se quiere probar
 * @param array<int, array{side?: string, hash?: string}> $path
 * @param string $rootHex Raíz anclada
 *
 * @return bool
 */
function merkleVerify($leafHex, array $path, $rootHex)
{
    try {
        $current = merkleLeaf($leafHex);

        foreach ($path as $step) {
            if (!is_array($step) || !isset($step['side'], $step['hash'])) {
                return false;
            }

            $sibling = merkleRawFromHex((string) $step['hash']);

            if ($step['side'] === 'right') {
                $current = merkleNode($current, $sibling);
            } elseif ($step['side'] === 'left') {
                $current = merkleNode($sibling, $current);
            } else {
                return false;
            }
        }

        return hash_equals(strtolower((string) $rootHex), bin2hex($current));
    } catch (Throwable $e) {
        return false;
    }
}
