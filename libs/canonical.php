<?php

/**
 * Codificación canónica: qué se firma exactamente, y cómo.
 *
 * Dos documentos JSON que significan lo mismo pueden serializarse distinto, y
 * entonces la misma firma verifica en una máquina y falla en la siguiente. Esa
 * es la forma silenciosa en que un protocolo de JSON firmado deja de ser
 * verificable, y por eso la §6.1 exige JCS (RFC 8785) para todo lo que se firma.
 *
 * Lo que hay aquí es un subconjunto estricto de JCS, no JCS entero: cubre
 * objetos, listas, cadenas, enteros, booleanos y null, y *rechaza* lo demás en
 * lugar de adivinarlo. Un flotante necesitaría el formato numérico de
 * ECMAScript, que PHP no produce; antes que emitir algo que parece canónico y
 * no lo es, canonicalJson() lanza. Nada de lo que firmamos lleva flotantes.
 */

/**
 * Serializa un valor como hay que serializarlo antes de firmar.
 *
 * @param mixed $value Los objetos van como arrays con claves de cadena; las
 *                     listas, como arrays con claves enteras desde cero
 *
 * @throws InvalidArgumentException Cuando el valor no se puede canonicalizar
 *                                  sin inventarse un convenio
 *
 * @return string JSON canónico en UTF-8, sin espacios superfluos
 */
function canonicalJson($value)
{
    $json = json_encode(canonicalPrepare($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    if ($json === false) {
        throw new InvalidArgumentException('El valor no se puede codificar como JSON: ' . json_last_error_msg());
    }

    return $json;
}

/**
 * Ordena las claves de cada objeto y rechaza lo que este subconjunto no cubre.
 *
 * @param mixed $value
 * @param int $depth
 *
 * @return mixed
 */
function canonicalPrepare($value, $depth = 0)
{
    if ($depth > 32) {
        throw new InvalidArgumentException('El valor anida demasiado para canonicalizarlo');
    }

    if (is_float($value)) {
        // JCS formatea los números como ECMAScript. PHP no, y una firma sobre
        // un número formateado a mano solo verificaría aquí.
        throw new InvalidArgumentException(
            'Este subconjunto de JCS no canonicaliza flotantes; usa un entero o una cadena',
        );
    }

    if (is_object($value)) {
        throw new InvalidArgumentException('Los objetos se pasan como arrays con claves de cadena');
    }

    if (!is_array($value)) {
        // Cadenas, enteros, booleanos y null no necesitan tratamiento.
        return $value;
    }

    $isList = array_keys($value) === range(0, count($value) - 1);

    if ($isList) {
        $out = [];
        foreach ($value as $item) {
            // El orden de una lista es significativo en JSON y JCS lo conserva.
            $out[] = canonicalPrepare($item, $depth + 1);
        }

        return $out;
    }

    $keys = [];
    foreach (array_keys($value) as $key) {
        $key = (string) $key;
        if (preg_match('/^[\x20-\x7e]*$/', $key) !== 1) {
            // JCS ordena las claves por unidad de código UTF-16. Para claves
            // ASCII eso es el orden de los bytes; fuera de ASCII los dos
            // criterios discrepan, así que preferimos rechazar antes que
            // ordenarlas mal y producir una firma que nadie puede comprobar.
            throw new InvalidArgumentException('Las claves de objeto deben ser ASCII para ordenarlas como exige JCS');
        }
        $keys[] = $key;
    }

    sort($keys, SORT_STRING);

    $out = [];
    foreach ($keys as $key) {
        $out[$key] = canonicalPrepare($value[$key], $depth + 1);
    }

    return $out;
}

/**
 * base64url sin relleno (§6.1).
 *
 * @param string $raw
 *
 * @return string
 */
function b64uEncode($raw)
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

/**
 * Decodificación estricta de base64url: una entrada mal formada devuelve false
 * y nunca bytes.
 *
 * En modo laxo, base64_decode() se salta en silencio los caracteres que no
 * reconoce, y por eso la §6.1 llama inalcanzables a las comprobaciones de error
 * que lo rodean en el código actual.
 *
 * @param string $text
 *
 * @return string|false
 */
function b64uDecode($text)
{
    if (!is_string($text) || $text === '') {
        return false;
    }

    if (preg_match('/^[A-Za-z0-9_-]+$/', $text) !== 1) {
        return false;
    }

    $padded = strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4);

    return base64_decode($padded, true);
}

/**
 * base32 del RFC 4648, sin relleno. Lo usa el identificador de nodo.
 *
 * @param string $raw
 *
 * @return string
 */
function base32NoPad($raw)
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    $len = strlen($raw);

    for ($i = 0; $i < $len; $i++) {
        $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
    }

    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        if (strlen($chunk) < 5) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        }
        $out .= $alphabet[bindec($chunk)];
    }

    return $out;
}

/**
 * Identificador de nodo (§5.1): autocertificante, derivado de las claves de
 * firma, así que no depende de que un registro diga quién eres.
 *
 * La especificación resume la clave Ed25519 seguida de la de ML-DSA. Este
 * demostrador todavía no tiene mitad clásica (la §4.1 la exige y el README la
 * cuenta entre lo que falta), así que el primer operando va vacío. Es la misma
 * fórmula con una parte ausente, no otra distinta, y eso implica que el día que
 * entre Ed25519 cambian todos los identificadores de nodo.
 *
 * @param string $mldsaPublicKey Clave pública ML-DSA cruda
 * @param string $ed25519PublicKey Clave pública Ed25519 cruda, vacía mientras no exista
 *
 * @return string "ip5:" seguido de 26 caracteres en base32
 */
function nodeId($mldsaPublicKey, $ed25519PublicKey = '')
{
    $digest = hash('sha3-256', $ed25519PublicKey . $mldsaPublicKey, true);

    return 'ip5:' . substr(base32NoPad($digest), 0, 26);
}

/**
 * RFC 3339 en UTC, como exige la §6.2.
 *
 * @param int|null $when
 *
 * @return string
 */
function rfc3339($when = null)
{
    return gmdate('Y-m-d\TH:i:s\Z', $when === null ? time() : $when);
}

/**
 * Lee una marca de tiempo RFC 3339 en UTC de forma estricta.
 *
 * @param string $text
 *
 * @return int|null Tiempo Unix, o null si el formato no es el que emitimos
 */
function parseRfc3339($text)
{
    if (!is_string($text) || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $text) !== 1) {
        return null;
    }

    $parsed = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s\Z', $text, new DateTimeZone('UTC'));

    return $parsed === false ? null : $parsed->getTimestamp();
}

// El receptor debe rechazar todo lo que se aparte más de esto de su propio
// reloj (§6.2, E_CLOCK_SKEW). Sin ese límite, un mensaje firmado sigue siendo
// reenviable mientras la firma valga.
if (!defined('MAX_CLOCK_SKEW')) {
    define('MAX_CLOCK_SKEW', 120);
}

/**
 * @param string $ts Marca RFC 3339 recibida
 * @param int|null $now
 *
 * @return bool Si la marca está lo bastante cerca del reloj de este nodo
 */
function clockSkewAcceptable($ts, $now = null)
{
    $parsed = parseRfc3339($ts);

    if ($parsed === null) {
        return false;
    }

    return abs(($now === null ? time() : $now) - $parsed) <= MAX_CLOCK_SKEW;
}
