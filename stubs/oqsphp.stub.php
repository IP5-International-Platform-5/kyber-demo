<?php

/**
 * Stubs de la extensión oqsphp (open-quantum-safe / liboqs-php).
 *
 * Este fichero NO se ejecuta ni se carga nunca: existe solo para que PHPStan y
 * el IDE conozcan la API de la extensión, que es nativa y no se puede analizar.
 * Se referencia únicamente desde la clave `scanFiles` de phpstan.neon.
 *
 * Las clases se declaran sin guardas `class_exists()` a propósito: PHPStan no
 * reconoce las declaraciones que están dentro de un condicional.
 *
 * OJO: las firmas de aquí son las del binding que usa ESTE repositorio
 * (`encapsulate` / `decapsulate`). El repositorio de referencia ip5-kyber-poc
 * usa una build con los nombres cortos (`encaps` / `decaps`) y su stub es
 * distinto. Si cambias de build, hay que ajustar este fichero.
 *
 * @see https://github.com/Muzosh/liboqs-php
 */

/**
 * Encapsulador de claves de liboqs.
 *
 * Los resultados salen **por referencia** en los parámetros; el valor de
 * retorno es el código de estado (OQS_SUCCESS si fue bien). Los `&` de las
 * firmas son imprescindibles: sin ellos PHPStan da por indefinidas las
 * variables que el método rellena.
 */
class OQS_KEYENCAPSULATION
{
    /** Longitud en bytes de la clave pública del algoritmo. */
    public int $length_public_key;

    /** Longitud en bytes de la clave privada del algoritmo. */
    public int $length_secret_key;

    /** Longitud en bytes del ciphertext del KEM. */
    public int $length_ciphertext;

    /** Longitud en bytes del secreto compartido. */
    public int $length_shared_secret;

    public function __construct(string $algorithm) {}

    /**
     * @param string $public_key se rellena con la clave pública (binario crudo)
     * @param string $secret_key se rellena con la clave privada (binario crudo)
     */
    public function keypair(&$public_key, &$secret_key): int {}

    /**
     * @param string $ciphertext    se rellena con el ciphertext KEM
     * @param string $shared_secret se rellena con el secreto compartido
     */
    public function encapsulate(&$ciphertext, &$shared_secret, string $public_key): int {}

    /**
     * @param string $shared_secret se rellena con el secreto compartido
     */
    public function decapsulate(&$shared_secret, string $ciphertext, string $secret_key): int {}
}

/** Alias del mismo encapsulador en otras builds de oqsphp. */
class OQS_KEM extends OQS_KEYENCAPSULATION
{
}

/** Código de retorno de éxito de liboqs. */
define('OQS_SUCCESS', 0);

/** Comprueba si liboqs tiene habilitado un algoritmo KEM concreto. */
function OQS_KEM_alg_is_enabled(string $algorithm): bool {}
