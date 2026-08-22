# Guía de estilo

Cómo se escribe el código en los repositorios Kyber de IP5. El flujo de trabajo
(issues, ramas, PRs) está en [`CONTRIBUTING.md`](../CONTRIBUTING.md).

> Este repositorio sigue la misma guía que
> [`ip5-kyber-poc`](https://github.com/IP5-International-Platform-5/ip5-kyber-poc),
> que es la implementación de referencia. Lo que cambia aquí es el estado de
> partida: el código es procedural, está escrito con tabuladores y no tiene
> tipado estricto. Lo de abajo es **hacia dónde va**, no lo que hay hoy.

**Casi nada de esto hay que recordarlo.** El formato lo aplican las herramientas
y lo verifica la CI:

```bash
composer estilo:aplicar    # PHP
npm run formato:aplicar    # JS, CSS y HTML
composer verificar         # sintaxis, estilo y análisis estático
```

### Estado de la migración

| Regla                              | Hoy                                    |
| ---------------------------------- | -------------------------------------- |
| PSR-12 y 4 espacios en PHP          | Configurado; **pasada pendiente**      |
| `declare(strict_types=1)`           | Desactivado; se activa fichero a fichero |
| PHPStan                             | Nivel 5 (el objetivo es 6)             |
| `camelCase` en variables            | El código actual usa `snake_case`      |
| Comentarios en español              | El código actual está en inglés        |

Nada de esto se arregla de golpe. La norma es: **el código que toques, lo dejas
según esta guía**; lo que no toques, se queda como está. La única excepción es
la pasada inicial de formato, que va en un PR propio de tipo `style:` sin
ningún cambio funcional dentro.

Este documento existe para lo que una herramienta no puede decidir: nombres,
idioma, estructura y las reglas propias de trabajar con criptografía.

---

## 1. Idioma

| Elemento                                     | Idioma                                    |
| -------------------------------------------- | ----------------------------------------- |
| Comentarios y PHPDoc                          | **Español**                               |
| Documentación, README, issues, PRs            | **Español**                               |
| Descripción de los commits                    | **Español**                               |
| Mensajes de error y de log                    | **Español**                               |
| Nombres de variables, funciones, clases       | **Inglés técnico**                        |
| Tipos de commit (`feat`, `fix`) y `BREAKING CHANGE` | **Inglés** (son etiquetas de herramienta) |
| Nombres de rama                               | **Español sin acentos**, en kebab-case    |
| Claves del JSON del protocolo                 | **Inglés, `snake_case`** (fijadas por el protocolo) |

Los identificadores van en inglés porque son la terminología literal de la
especificación: `Kem`, `encapsulate`, `decapsulate`, `sharedSecret`,
`ciphertext`, `publicKey` son los nombres que usan ML-KEM (FIPS 203) y liboqs.
Traducirlos rompería la correspondencia con la norma y con la extensión.

Los acentos y la `ñ` se escriben **siempre** en comentarios y documentación.
Los ficheros son UTF-8 sin BOM; no hay motivo para escribir "sesion" o "criptografia".

El código heredado tiene los comentarios en inglés. No hay que traducirlos en
masa: se traducen los del código que se toque por otro motivo. El texto que ve
el usuario en la demo es aparte y va en el idioma que decida el diseño de la
interfaz.

---

## 2. Formato

Lo fija `.editorconfig` y lo aplica `.php-cs-fixer.dist.php`:

- **PSR-12** como base, más las migraciones de PHP 8.1.
- Indentación de **4 espacios** en PHP; **2 espacios** en JS, CSS, HTML, JSON,
  YAML y Dockerfiles. Nunca tabuladores — el código heredado los usa y se
  convierten en la pasada inicial de formato.
- Fin de línea **LF** siempre, también en Windows (lo garantiza `.gitattributes`).
- **UTF-8** sin BOM, salto de línea final, sin espacios al final de línea.
- **Comillas simples** salvo que la cadena interpole variables o lleve `\n`.
- **Coma final** en arrays, argumentos y parámetros multilínea: hace que añadir
  un elemento sea un diff de una sola línea.
- Comentarios de una línea con `//`, nunca con `#`.
- Longitud de línea: no hay límite duro, pero por encima de ~120 caracteres
  conviene partir. En Markdown, ~100.

---

## 3. Nombres

| Elemento                       | Convención                       | Ejemplo                          |
| ------------------------------ | -------------------------------- | -------------------------------- |
| Clase, interfaz, enum, trait   | `PascalCase`, en singular        | `SessionStore`, `SymmetricCipher` |
| Método y función               | `camelCase`, verbo primero       | `encapsulate()`, `hasSharedSecret()` |
| Variable y propiedad           | `camelCase`                      | `$sharedSecret`, `$expiresAt`    |
| Constante                      | `UPPER_SNAKE_CASE`               | `DEFAULT_ALG`, `TAG_LEN`         |
| Clave de array de configuración | `snake_case`                     | `session_ttl`, `kem_alg`         |
| Clave del JSON del protocolo   | `snake_case`                     | `session_id`, `encrypted_data`   |
| Fichero de clase               | Igual que la clase               | `src/SessionStore.php`           |
| Fichero de función suelta      | `snake_case` (uso actual)        | `libs/kyber_utils.php`, `get_public_key.php` |
| Fichero de script o doc        | `kebab-case`                     | `setup-linux.sh`, `guia-de-estilo.md` |
| Clase e id de CSS              | `kebab-case`                     | `.key-panel`, `#shared-secret`   |

Reglas de fondo:

- **Sin abreviaturas inventadas.** `$sharedSecret`, no `$ss`. `$ciphertext`, no `$ct`.
  Las siglas del dominio sí se usan tal cual: `kem`, `iv`, `tag`, `aes`, `gcm`.
- El código PHP heredado usa `snake_case` en variables (`$shared_secret`,
  `$public_key`). **No lo renombres en masa**: los nombres coinciden con las
  claves del JSON del protocolo y con la API de `oqsphp`, y un renombrado
  general sería un diff imposible de revisar. En código nuevo, `camelCase`.
- Las siglas dentro de un nombre en PascalCase se escriben como palabra:
  `KyberClient`, no `KYBERClient`; `parseJson`, no `parseJSON`.
- Los métodos que devuelven un booleano empiezan por `is`, `has`, `can` o `should`:
  `isExpired()`, `hasKeypair()`.
- El nombre dice **qué** es, no **cómo** está hecho: `SessionStore`, no
  `SessionArrayWrapper`.

---

## 4. PHP

### Tipado estricto

En **código nuevo**, todo fichero PHP empieza así:

```php
<?php

declare(strict_types=1);
```

Sin él, PHP convierte silenciosamente entre `int`, `float` y `string`, y en
código que manipula bytes eso es una vía directa a un fallo criptográfico
difícil de ver.

En los ficheros heredados se añade **de uno en uno**, comprobando que la demo
sigue funcionando después. Por eso la regla `declare_strict_types` está a
`false` en `.php-cs-fixer.dist.php`: activarla en masa cambiaría el
comportamiento de once ficheros a la vez y sin pruebas que lo respalden.

### Tipos

- En código nuevo, **todo** parámetro, retorno y propiedad lleva tipo declarado.
  PHPStan está hoy en nivel 5; el nivel 6, que ya lo exige, es el objetivo.
- Los arrays llevan su tipo en PHPDoc, porque PHP no puede expresarlo:

```php
/**
 * @param array<string, mixed> $body
 *
 * @return array{ciphertext: string, shared_secret: string}
 */
```

- Usa `array{...}` (forma de la estructura) en lugar de `array<string, mixed>`
  siempre que la estructura sea conocida: documenta mucho mejor.

### Clases

- `final` por defecto. Se quita solo cuando alguien necesita heredar de verdad.
- `readonly` en toda propiedad que no cambie tras el constructor.
- Promoción de propiedades en el constructor cuando no complique la lectura.
- Orden de los miembros: constantes → propiedades → constructor → métodos
  públicos → protegidos → privados. Lo aplica el fixer.
- Una clase por fichero, con el mismo nombre.

### Excepciones y errores

- El código actual devuelve arrays `['error' => '…']` en vez de lanzar
  excepciones. Es coherente consigo mismo, así que **respétalo dentro de
  `libs/`**: mezclar los dos estilos es peor que cualquiera de los dos. En
  código nuevo que no tenga que encajar con esas funciones, lanza excepciones.
- El mensaje explica **qué** falló y **qué se esperaba**:

```php
throw new \RuntimeException(
    'El secreto compartido debe ser de 32 bytes para AES-256-GCM; recibidos ' . strlen($key) . '.',
);
```

- **Nunca** metas material criptográfico en el mensaje de una excepción: acaba en
  un log, en una respuesta HTTP o en un informe de error.
- Comparaciones siempre estrictas (`===`, `!==`). Lo fuerza el fixer.

### Comentarios

- Comenta el **porqué**, no el qué. El *qué* está en el código.
- Un comentario que repite el nombre del método sobra.
- Los comentarios que explican una decisión de protocolo o de seguridad son
  **obligatorios** y valen su peso en oro:

```php
// Guarda la clave simétrica y DESTRUYE el par asimétrico (forward secrecy):
// a partir de aquí, ni el servidor puede recuperar los mensajes anteriores.
SessionStore::storeSharedSecretAndDropKeypair($sharedSecret);
```

- Los pendientes se marcan `// TODO(#42): …` con el número de issue. Un TODO sin
  issue es un TODO que nadie va a hacer.

---

## 5. Reglas de criptografía

No son estilo: son correctitud. Un PR que las incumple no se mezcla.

- **Aleatoriedad** solo con `random_bytes()`. Nunca `rand()`, `mt_rand()`,
  `uniqid()` ni `openssl_random_pseudo_bytes()` sin comprobar el flag.
- **IV único por mensaje**: 12 bytes de `random_bytes(12)` en cada cifrado.
  Reutilizar un IV con la misma clave en GCM rompe la confidencialidad *y* la
  autenticidad. No hay excepción "para depurar".
- **El tag GCM viaja aparte**, nunca concatenado al ciphertext.
- **Comparación de secretos** con `hash_equals()`, nunca con `===`: `===` sale
  antes en el primer byte distinto y filtra información por tiempo.
- **Destruir el material de clave** en cuanto deje de hacer falta, y dejarlo
  explícito en el código con un comentario.
- **Nada de secretos en logs**, ni en `var_dump`, `echo`, `error_log` o
  `print_r`, ni siquiera temporalmente durante la depuración. Si necesitas ver
  un secreto, imprime su longitud o un hash truncado.
- **No inventes primitivas.** El cifrado es AES-256-GCM vía `openssl_*`, el KEM
  es Kyber/ML-KEM vía `oqsphp`. Ningún XOR artesanal, ningún "cifrado ligero".
- Los valores de configuración criptográfica (algoritmo, TTL, tamaños) van en
  `config.php`, nunca incrustados en medio del código.

---

## 6. Estructura del proyecto

```
libs/kyber_utils.php    Núcleo criptográfico: KEM y AES-GCM
api_server/             Endpoints del lado servidor (get_public_key, …)
app/                    Endpoints del lado cliente (encrypt_message, …)
public/                 Front controller y rutas /app y /api_server
src/                    Front-end: JavaScript y CSS (lo compila Vite)
docker/                 Dockerfiles y configuración de nginx
scripts/                Utilidades de desarrollo y configuración
stubs/                  Stubs de extensiones nativas (solo PHPStan y el IDE)
docs/                   Documentación
liboqs-php/             Submódulo de terceros. NO se toca.
.github/                Plantillas de issue/PR y workflows
```

Dónde va cada cosa:

- La demo simula **dos roles en el mismo navegador**: `app/` es el cliente y
  `api_server/` es el servidor. Esa separación es didáctica y hay que
  mantenerla: no metas lógica de servidor en `app/` ni al revés.
- La criptografía vive en `libs/kyber_utils.php`. Los endpoints solo validan
  la entrada, llaman a esas funciones y serializan la respuesta.
- `src/` aquí es el **front-end**, no el dominio PHP (al contrario que en
  `ip5-kyber-poc`). Es una diferencia entre los dos repositorios que conviene
  tener presente.
- **`liboqs-php/` es un submódulo de terceros.** No se edita, no se formatea y
  no se analiza. Si aparece en un `git status`, es un accidente.

---

## 7. Front-end y otros lenguajes

El formato lo aplica Prettier (`npm run formato:aplicar`), configurado en
`.prettierrc.json`. Su alcance son **JavaScript, CSS y HTML**: Markdown, YAML y
JSON quedan fuera a propósito, porque reflowea el texto y rompe las tablas de la
documentación. Ver `.prettierignore`. Lo de abajo es lo que Prettier no decide.

### JavaScript

- 2 espacios, comillas simples, sin punto y coma final (estilo del código actual).
- `const` por defecto, `let` si hay reasignación. Nunca `var`.
- `camelCase` para variables y funciones, `PascalCase` para clases.
- `async/await` en vez de cadenas de `.then()`.
- Nada de secretos ni claves en `console.log`. La demo **sí enseña material
  criptográfico en pantalla**, porque ese es su cometido, pero eso es una
  decisión de interfaz explícita: no es lo mismo que dejarlo en la consola o en
  un log del servidor.

### CSS

- 2 espacios, clases en `kebab-case`.
- Variables CSS en `:root` para colores y espaciados; nada de valores mágicos
  repetidos.
- Nada de estilos en línea desde JavaScript cuando puedan ser una clase.

### Docker y nginx

- Una instrucción por línea en los `Dockerfile`, con las capas ordenadas de
  menos a más cambiante para aprovechar la caché.
- Las imágenes base van **con versión fijada** (`php:8.3-fpm-alpine`), nunca
  `latest`: una PoC criptográfica que cambia de versión de PHP sola es una
  fuente de fallos irreproducibles.
- Ninguna credencial ni secreto dentro de una imagen. Van por variable de
  entorno, y el `.env` no se versiona.

### Markdown

- Encabezados con `#`, listas con `-`, código siempre en bloques con el lenguaje
  indicado.
- Una idea por párrafo y líneas de ~100 caracteres, para que los diffs sean legibles.

### Shell

- `#!/usr/bin/env bash` y `set -euo pipefail` al principio de todo script.
- Variables siempre entrecomilladas: `"$var"`.

### YAML

- 2 espacios, nunca tabuladores. Cadenas entrecomilladas cuando puedan
  interpretarse como número o booleano (`'8.1'`, no `8.1`).

---

## 8. Qué no se sube al repositorio

Lo cubre `.gitignore`, pero la responsabilidad es de quien hace el commit:

- Claves de cualquier tipo: `.pem`, `.key`, `.ppk`, claves privadas o públicas
  generadas, secretos compartidos.
- `.env` y cualquier configuración con credenciales reales. Sí se sube
  `.env.example` con valores de mentira.
- `vendor/`, `node_modules/`, `dist/`, cachés de herramientas.
- El contenido de `keys/`, `app/keys/` y `api_server/keys/`: son las claves que
  la demo genera al ejecutarse.
- Ficheros del IDE: `.idea/`, `.vscode/`.
- Volcados de sesión PHP, logs, ciphertext o material capturado de una ejecución real.
- `dist/`, `node_modules/`, `vendor/`.
- Cambios accidentales en el submódulo `liboqs-php`.

Si un secreto llega a subirse: **rótalo primero**, reescribe el historial
después. Un secreto que ha estado en un remoto está comprometido aunque se borre
el commit.
