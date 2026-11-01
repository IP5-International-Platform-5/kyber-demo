<?php

/**
 * Sellado de tiempo cualificado de la raíz de época (§11.3).
 *
 * Un `ts` que se declara uno mismo no vale nada frente a un tercero: lo escribe
 * el nodo al que le conviene la fecha. Un sello RFC 3161 cualificado sí vale,
 * porque es un tercero de confianza el que afirma la hora. Sin esto, "no
 * repudio" es una afirmación técnica sin efecto jurídico y la premisa P2
 * (legalidad) no se cumple.
 *
 * Así que aquí está implementado de verdad —un TimeStampReq en DER, enviado a
 * una TSA, y el token guardado tal cual—, pero sale *desactivado*. En este
 * demostrador no hay ninguna TSA cualificada, y lo honesto en una evidencia es
 * un sello ausente con su ausencia declarada, nunca una fecha que nos hemos
 * inventado.
 *
 * Pon QSLP_TSA_URL apuntando a una TSA (FreeTSA y otras responden sin
 * autenticación) y el token empieza a viajar dentro del paquete de evidencia.
 *
 * El resumen es SHA-256 y no SHA3-256 a propósito: es lo que aceptan las TSA
 * desplegadas y lo que comprueba `openssl ts -verify`. El token cubre entonces
 * el SHA-256 de la raíz de Merkle, que sigue siendo un compromiso con esa raíz
 * exacta.
 */

require_once __DIR__ . '/canonical.php';

if (!defined('TSA_TIMEOUT')) {
    define('TSA_TIMEOUT', 5);
}

/**
 * @return string|null Punto final de la TSA configurado, o null si está desactivado
 */
function tsaUrl()
{
    $url = trim((string) getenv('QSLP_TSA_URL'));

    if ($url === '' || preg_match('#^https?://#', $url) !== 1) {
        return null;
    }

    return $url;
}

/**
 * @param int $length
 *
 * @return string Octetos de longitud en DER
 */
function derLength($length)
{
    if ($length < 0x80) {
        return chr($length);
    }

    $bytes = '';
    while ($length > 0) {
        $bytes = chr($length & 0xff) . $bytes;
        $length >>= 8;
    }

    return chr(0x80 | strlen($bytes)) . $bytes;
}

/**
 * @param int $tag
 * @param string $content
 *
 * @return string
 */
function derTlv($tag, $content)
{
    return chr($tag) . derLength(strlen($content)) . $content;
}

/**
 * @param string $raw Magnitud en big-endian
 *
 * @return string INTEGER de DER, siempre positivo
 */
function derPositiveInteger($raw)
{
    $raw = ltrim($raw, "\x00");

    if ($raw === '') {
        $raw = "\x00";
    }

    if (ord($raw[0]) & 0x80) {
        // Con el bit más alto a uno se leería como un entero negativo en
        // complemento a dos.
        $raw = "\x00" . $raw;
    }

    return derTlv(0x02, $raw);
}

/**
 * Construye el TimeStampReq del RFC 3161 §2.4.1.
 *
 * @param string $rawDigest Resumen SHA-256 de 32 bytes de lo que se sella
 * @param string $nonce 8 bytes aleatorios, para que una respuesta reenviada se detecte
 *
 * @return string DER
 */
function tsaRequest($rawDigest, $nonce)
{
    // 2.16.840.1.101.3.4.2.1 — sha256
    $sha256Oid = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";

    $algorithm = derTlv(0x30, $sha256Oid . "\x05\x00");
    $imprint = derTlv(0x30, $algorithm . derTlv(0x04, $rawDigest));

    return derTlv(0x30, derTlv(0x02, "\x01")
        . $imprint
        . derPositiveInteger($nonce)
        // certReq TRUE: pedimos que la TSA incluya su certificado, o el token
        // no se podrá verificar sin conexión más adelante (§19.3, §19.7).
        . derTlv(0x01, "\xff"));
}

/**
 * Pide a la TSA configurada que selle un resumen.
 *
 * Nunca lanza: un sello que no se pudo obtener se registra como ausente, con su
 * motivo. Una evidencia con un campo que falta y una explicación es utilizable;
 * una que afirma en silencio un sello que no tiene, no.
 *
 * @param string $rawData Bytes que sellar, p. ej. los 32 bytes crudos de la raíz
 *
 * @return array<string, mixed>
 */
function tsaStamp($rawData)
{
    $url = tsaUrl();
    $digest = hash('sha256', $rawData, true);

    $absent = [
        'present' => false,
        'imprint_alg' => 'sha256',
        'imprint' => bin2hex($digest),
    ];

    if ($url === null) {
        return $absent + [
            'reason' => 'QSLP_TSA_URL no está configurada: la §11.3 exige una TSA cualificada '
                . 'y este despliegue no tiene ninguna',
        ];
    }

    $request = tsaRequest($digest, random_bytes(8));
    $response = tsaPost($url, $request);

    if ($response === null) {
        return $absent + [
            'reason' => 'la TSA de ' . $url . ' no devolvió un TimeStampResp utilizable',
            'tsa_url' => $url,
        ];
    }

    return [
        'present' => true,
        'format' => 'TimeStampResp del RFC 3161, en DER y base64url',
        'imprint_alg' => 'sha256',
        'imprint' => bin2hex($digest),
        'tsa_url' => $url,
        'token' => b64uEncode($response),
        'qualified' => (bool) getenv('QSLP_TSA_QUALIFIED'),
    ];
}

/**
 * @param string $url
 * @param string $request TimeStampReq en DER
 *
 * @return string|null TimeStampResp en DER
 */
function tsaPost($url, $request)
{
    if (function_exists('curl_init')) {
        $handle = curl_init($url);

        if ($handle === false) {
            return null;
        }

        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $request,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => TSA_TIMEOUT,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/timestamp-query',
                'Accept: application/timestamp-reply',
            ],
        ]);

        $body = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        return ($body === false || $status !== 200 || $body === '') ? null : (string) $body;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\n",
            'content' => $request,
            'timeout' => TSA_TIMEOUT,
            'ignore_errors' => true,
        ],
    ]);

    $body = @file_get_contents($url, false, $context);

    return ($body === false || $body === '') ? null : $body;
}
