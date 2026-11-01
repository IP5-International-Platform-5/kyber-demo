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

/**
 * Raíz del árbol vacío.
 *
 * La §19.5 exige que toda época se ancle, también las que no tuvieron
 * recibos: un hueco en la numeración es por sí mismo evidencia de omisión, y
 * sin esto la ausencia de una época no se distingue de «no pasó nada». Así que
 * el árbol vacío necesita una raíz definida, y se define con su propia
 * etiqueta para que no pueda coincidir con la de ninguna hoja ni nodo.
 *
 * @return string 64 caracteres hexadecimales
 */
function merkleEmptyRoot()
{
    return hash('sha3-256', "\x02" . 'QSLP1-demo empty tree');
}

/**
 * Mayor potencia de dos menor o igual que $n.
 *
 * @param int $n
 *
 * @return int
 */
function merkleFullPrefix($n)
{
    $k = 1;
    while ($k * 2 <= $n) {
        $k *= 2;
    }

    return $k;
}

/**
 * Prueba de consistencia entre el árbol de las primeras $m hojas y el de las
 * $n primeras (RFC 6962 §2.1.2).
 *
 * Esto es lo que demuestra que un log no reescribió su historia: que el árbol
 * de ahora **contiene** al de antes como prefijo, y no es otro árbol distinto
 * que casualmente tiene más hojas. El paso 5 lo hacía entregando todas las
 * entradas intermedias, que para un diario de demostración bastaba; un log de
 * transparencia necesita que el coste sea logarítmico, porque si no, auditar
 * sale caro justo cuando el log es grande.
 *
 * @param string[] $leavesHex Hojas del árbol grande
 * @param int $m Tamaño del árbol antiguo
 *
 * @throws InvalidArgumentException Si los tamaños no tienen sentido
 *
 * @return string[] Hashes de la prueba, en el orden en que se consumen
 */
function merkleConsistencyProof(array $leavesHex, $m)
{
    $leavesHex = array_values($leavesHex);
    $n = count($leavesHex);
    $m = (int) $m;

    if ($m < 1 || $m > $n) {
        throw new InvalidArgumentException('El tamaño del árbol antiguo tiene que estar entre 1 y ' . $n);
    }

    return merkleSubProof($m, $leavesHex, true);
}

/**
 * SUBPROOF del RFC 6962. El indicador $known dice si el árbol antiguo ya es
 * conocido por quien verifica: cuando lo es, su raíz no viaja en la prueba,
 * porque ya la tiene firmada en el checkpoint.
 *
 * @param int $m
 * @param string[] $leavesHex
 * @param bool $known
 *
 * @return string[]
 */
function merkleSubProof($m, array $leavesHex, $known)
{
    $n = count($leavesHex);

    if ($m === $n) {
        return $known ? [] : [bin2hex(merkleRootRaw($leavesHex))];
    }

    $k = merkleSplit($n);

    if ($m <= $k) {
        $proof = merkleSubProof($m, array_slice($leavesHex, 0, $k), $known);
        $proof[] = bin2hex(merkleRootRaw(array_slice($leavesHex, $k)));

        return $proof;
    }

    $proof = merkleSubProof($m - $k, array_slice($leavesHex, $k), false);
    $proof[] = bin2hex(merkleRootRaw(array_slice($leavesHex, 0, $k)));

    return $proof;
}

/**
 * Comprueba una prueba de consistencia sin ver ninguna hoja.
 *
 * Recompone las dos raíces a partir de la prueba y las compara con las dos que
 * el log firmó. Si el log reescribió algo, las raíces no salen.
 *
 * @param int $m Tamaño del árbol antiguo
 * @param int $n Tamaño del árbol nuevo
 * @param string[] $proof
 * @param string $rootMHex Raíz antigua, de un checkpoint firmado
 * @param string $rootNHex Raíz nueva, de otro checkpoint firmado
 *
 * @return bool
 */
function merkleVerifyConsistency($m, $n, array $proof, $rootMHex, $rootNHex)
{
    $m = (int) $m;
    $n = (int) $n;

    if ($m < 1 || $n < $m) {
        return false;
    }

    if ($m === $n) {
        // Nada que demostrar: el mismo árbol. La prueba tiene que venir vacía,
        // y las dos raíces tienen que ser la misma.
        return $proof === [] && hash_equals(strtolower($rootMHex), strtolower($rootNHex));
    }

    try {
        $cursor = 0;
        $roots = merkleFoldConsistency($m, $n, array_values($proof), $cursor, true, merkleRawFromHex(strtolower($rootMHex)));

        if ($cursor !== count($proof)) {
            // Sobran hashes: una prueba con material de más no es una prueba.
            return false;
        }

        return hash_equals(strtolower($rootMHex), bin2hex($roots[0]))
            && hash_equals(strtolower($rootNHex), bin2hex($roots[1]));
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Espejo exacto de merkleSubProof(): recompone a la vez la raíz antigua y la
 * nueva consumiendo la prueba en el mismo orden en que se generó.
 *
 * @param int $m
 * @param int $n
 * @param string[] $proof
 * @param int $cursor Posición de lectura, por referencia
 * @param bool $known
 * @param string $rootMRaw Raíz antigua conocida, en crudo
 *
 * @return array{0: string, 1: string} Raíz antigua y raíz nueva, en crudo
 */
function merkleFoldConsistency($m, $n, array $proof, &$cursor, $known, $rootMRaw)
{
    if ($m === $n) {
        if ($known) {
            return [$rootMRaw, $rootMRaw];
        }

        $hash = merkleTakeProofHash($proof, $cursor);

        return [$hash, $hash];
    }

    $k = merkleSplit($n);

    if ($m <= $k) {
        $left = merkleFoldConsistency($m, $k, $proof, $cursor, $known, $rootMRaw);
        $right = merkleTakeProofHash($proof, $cursor);

        return [$left[0], merkleNode($left[1], $right)];
    }

    $right = merkleFoldConsistency($m - $k, $n - $k, $proof, $cursor, false, $rootMRaw);
    $left = merkleTakeProofHash($proof, $cursor);

    return [merkleNode($left, $right[0]), merkleNode($left, $right[1])];
}

/**
 * @param string[] $proof
 * @param int $cursor
 *
 * @throws InvalidArgumentException Si la prueba se queda corta
 *
 * @return string Bytes crudos
 */
function merkleTakeProofHash(array $proof, &$cursor)
{
    if (!isset($proof[$cursor])) {
        throw new InvalidArgumentException('La prueba de consistencia se queda corta');
    }

    $raw = merkleRawFromHex(strtolower((string) $proof[$cursor]));
    $cursor++;

    return $raw;
}
