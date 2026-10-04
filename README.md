# Kyber Post-Quantum Cryptography PoC

Key exchange and message encryption using **ML-KEM-768** (FIPS 203, the standardised form of Kyber), exposed as a PHP API with an interactive web demo.

> **Proof of concept.** This repository illustrates a Kyber-based key exchange and message flow for learning and experimentation. It is **not** a hardened product: there is no authentication on the APIs, there are no signatures, and many operational concerns are out of scope. **Do not** deploy it as-is for real users or sensitive data. See [Security](#security).



## Table of contents

- [Entorno de trabajo](#entorno-de-trabajo)
- [Installation](#installation)
- [Architecture](#architecture)
- [API (endpoints)](#api-endpoints)
- [Communication flow](#communication-flow)
- [Demo](#demo)
- [Development](#development)
- [Security](#security)



## Entorno de trabajo

**El entorno de referencia es el contenedor, no tu máquina.** La demo solo se
ejecuta dentro de Docker, porque necesita la extensión `oqsphp`, que no se
instala con el gestor de paquetes de ninguna distribución.

| Componente | Versión fijada | Dónde se fija |
| ---------- | -------------- | ------------- |
| PHP (ejecución) | 8.4 | `docker/php/Dockerfile`, imagen fijada por digest |
| PHP (mínimo soportado) | 8.1 | `composer.json`: `require.php` y `config.platform.php` |
| liboqs | 0.16.0 | `docker/php/Dockerfile`, `ARG LIBOQS_TAG` |
| oqsphp (binding) | commit `8f929d2` | submódulo `liboqs-php` |
| Node | 24 | `.nvmrc`, `engines` de `package.json` e imágenes por digest |
| Nginx | `alpine` | `docker/nginx/Dockerfile`, imagen fijada por digest |
| Algoritmo KEM | ML-KEM-768 (FIPS 203) | constante `KEM_ALG` en `libs/kyber_utils.php` |

### Qué hace falta en local

| Herramienta | Para qué | Instalación en Arch/Manjaro |
| ----------- | -------- | --------------------------- |
| Docker + Compose | Ejecutar la demo. Es lo único imprescindible | `sudo pacman -S docker docker-compose` |
| PHP 8.x | `php -l` y las herramientas de estilo. **No ejecuta la demo** | `sudo pacman -S php` |
| Composer | Dependencias de desarrollo | `sudo pacman -S composer` |
| Node 24 | Solo si tocas el front fuera del contenedor | `nvm use` |

`docker compose` es un plugin del cliente de Docker: si `docker compose version`
responde «unknown command», falta el paquete `docker-compose`, aunque el demonio
esté funcionando.

La extensión `sodium` hará falta para la zeroización de material de clave. El
módulo viene con PHP pero llega desactivado: hay que descomentar
`extension=sodium` en `/etc/php/php.ini`.

### Por qué por digest y no por etiqueta

Una etiqueta como `php:8.4-fpm-bookworm` cambia de contenido sin cambiar de
nombre, y el guion de compilación de `liboqs-php` clonaba la rama `main` de
liboqs. Con las dos cosas juntas, dos compilaciones en fechas distintas podían
traer conjuntos de algoritmos distintos: en liboqs 0.15.0 desapareció Dilithium
y en 0.16.0, SPHINCS+. Para un proyecto que aspira a que sus registros tengan
valor probatorio, no poder decir con qué código se generó una firma es un
defecto, no una molestia.

La contrapartida es real: **fijar por digest congela también las actualizaciones
de seguridad de la imagen base**. Conviene revisarlas una vez al mes, y ante
cualquier aviso, en un commit propio que diga qué sube y por qué:

```bash
docker pull php:8.4-fpm-bookworm
docker inspect --format '{{index .RepoDigests 0}}' php:8.4-fpm-bookworm
docker manifest inspect php:8.4-fpm-bookworm@sha256:<el que vayas a fijar>
```

El tercer comando no es opcional: **un digest puede pudrirse**. Estas imágenes se
reconstruyen a menudo y el registro deja de servir los manifiestos que se quedan
sin etiqueta, así que un digest tomado de la API web puede caducar en horas.
Aquí pasó: se fijó uno que el registro ya no sirve y la compilación seguía
funcionando en local —la imagen estaba en el almacén—, pero en una máquina limpia
o en la CI el `FROM` habría fallado. Toma siempre el digest que verifica el
propio demonio, y confirma que `manifest inspect` responde en lugar de
`manifest verification failed` antes de confirmarlo en git.

### Lo que todavía no está fijado

- Los *runners* de la CI usan `ubuntu-latest`, que es una etiqueta móvil, y las
  acciones se fijan por versión mayor (`actions/checkout@v4`), no por commit.
- `composer.json` y `composer.lock` reales viven en la rama del protocolo, sin
  mezclar: en `main` el `composer.json` está vacío.
- `package-lock.json` no concuerda hoy con `package.json`, así que `npm ci`
  —y por tanto la imagen de Nginx— no compila hasta regenerarlo.

## Installation

Pick one setup guide:


| Method                           | Guide                              | When to use                                 |
| -------------------------------- | ---------------------------------- | ------------------------------------------- |
| **Docker (Windows/Linux/macOS)** | [SETUP-DOCKER.md](SETUP-DOCKER.md) | Fastest try-out; no local PHP/oqsphp build. |
| **Linux (Debian/Ubuntu)**        | [SETUP-LINUX.md](SETUP-LINUX.md)   | PHP + **oqsphp** on the host; dev with `php -S` and Vite, or Nginx + PHP-FPM. |


Both need the **liboqs-php** git submodule (`git clone --recursive` or `git submodule update --init --recursive`).

## Architecture

The **browser** is the front end. Two logical backends cooperate over HTTP:


| Path          | Role                                                                                                    |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `app/`        | User application backend — encapsulation (`get_shared_secret`) and AES-GCM encrypt (`encrypt_message`). |
| `api_server/` | Kyber server API — public key, decapsulation (`set_shared_secret`), decrypt (`decrypt_message`).        |
| `libs/`       | Shared PHP helpers (`kyber_utils.php`).                                                                 |
| `dist/`       | Built static front (Vite).                                                                              |


Each backend has its own `config.php` and `cors_headers.php`. In a real deployment these would be different hosts; here they are two folders on one machine. **No key material is written to disk:** each side keeps its own copy of the shared secret in the ephemeral store (APCu), under a session identifier both ends derive separately. Sessions last five minutes. If steps get out of order, start again from “get public key”; there is nothing to delete.

The `demo.html` page groups calls that would normally go to `app` and `api_server` separately.

## API (endpoints)



### 1. Get public key

- **URL:** `/api_server/get_public_key`
- **Method:** POST
- **Body:**
  ```json
  {
    "client_nonce": "32_random_bytes_base64"
  }
  ```
- **Response:** `key_id`, `public_key`, `public_key_length`, `server_nonce`,
  `identity`, `identity_fingerprint` and `signature`.

  The key pair is **ephemeral**: generated for this request, the private half
  never leaves memory, destroyed after one decapsulation.

  The `signature` is ML-DSA-65 over a transcript covering both nonces, the
  `key_id`, the ephemeral key and the identity. **It is what stops a
  man-in-the-middle swapping the key for their own** (§7.2); without it the
  encryption protects you from whoever is listening, but not from whoever is
  in the middle. The client nonce is there so an old signed offer cannot be
  replayed at you.



### 2. Create shared secret

- **URL:** `/app/get_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "public_key": "server_public_key_base64",
    "key_id": "handle_from_step_1",
    "client_nonce": "the_one_sent_in_step_1",
    "server_nonce": "from_step_1",
    "identity": "server_identity_base64",
    "signature": "server_signature_base64"
  }
  ```
- **Response:** `sid`, `ciphertext`, `secret_fingerprint`, `confirmation`, this
  node's own `identity` and `signature`, and the fingerprints of both parties.
- **409** if the signature does not cover the offer, or if the server identity
  differs from the pinned one.

  The shared secret itself never leaves the backend. The `sid` is **derived**
  from the secret and the transcript, not invented: both ends reach the same
  value on their own, so a client cannot pick or fix one (QSLP/1 §7.4).



### 3. Send shared secret

- **URL:** `/api_server/set_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "ciphertext": "kyber_ciphertext_base64",
    "key_id": "handle_from_step_1",
    "identity": "client_identity_base64",
    "signature": "client_signature_base64"
  }
  ```
- **Response:** `sid`, `secret_fingerprint` and `confirmation`, which must match
  the ones the app side reported, plus both fingerprints.
- **409** if the `key_id` is unknown, expired or already used; if the client
  signature does not cover the answer; or if the client identity changed.



### 4. Encrypt message

- **URL:** `/app/encrypt_message`
- **Method:** POST
- **Body:**
  ```json
  {
    "message": "plaintext_message",
    "sid": "session_identifier"
  }
  ```
- **Response:** `encrypted_data`, `iv`, and `tag` (AES-256-GCM), all **base64**.



### 5. Decrypt message

- **URL:** `/api_server/decrypt_message`
- **Method:** POST
- **Body:**
  ```json
  {
    "encrypted_data": "base64_ciphertext",
    "iv": "base64_iv",
    "tag": "base64_auth_tag",
    "sid": "session_identifier"
  }
  ```
- **Response:** `message` field (plaintext).
- **409** if the session is unknown or expired. There is no stored secret to
  fall back on, which is the point.



## Communication flow

1. Front requests the public key: `/api_server/get_public_key`.
2. User app backend encapsulates via `/app/get_shared_secret`.
3. Front sends the ciphertext: `/api_server/set_shared_secret`.
4. Server decapsulates with its private key and derives the same shared secret.
5. User app backend encrypts messages: `/app/encrypt_message`.
6. Server decrypts: `/api_server/decrypt_message`.



## Demo

The `demo.html` page walks through the flow by calling the backends. The browser **does not** run Kyber in JavaScript: post-quantum work is done by **PHP** in `app/` and `api_server/`.

- Fetches the server public key.
- Agrees the shared secret via the API (Kyber on the server).
- Encrypts and decrypts with AES-GCM using that secret.

A browser-only front would need WebAssembly or another Kyber module; here encapsulation and encrypt live in `app/` as the user backend, separate from `api_server/` on a real network.

URLs depend on your setup — see [SETUP-DOCKER.md](SETUP-DOCKER.md) (port **8080** or **5173** with `dev`) or [SETUP-LINUX.md](SETUP-LINUX.md).

## Development

While editing, use **`npm run docker:dev`** or **`npm run dev` / `npm run full`** (Linux) — Vite serves `src/main.js` and HTML from disk; **F5** shows changes. Plain **`docker compose up`** on **8080** serves a built `dist/` and will **not** reflect `main.js` edits until you rebuild **web**.

| Command            | Description                                                            |
| ------------------ | ---------------------------------------------------------------------- |
| `npm run dev`      | Vite dev server on the host (proxies `/app` and `/api_server` to PHP). |
| `npm run full`     | Host: `php -S` + Vite (see [SETUP-LINUX.md](SETUP-LINUX.md)).          |
| `npm run build`    | Writes static assets to `dist/`.                                       |
| `npm run preview`  | Serves `dist/` with API proxy (`vite.config.js`).                      |
| `npm run docker:*` | Docker workflows — see [SETUP-DOCKER.md](SETUP-DOCKER.md).             |


`npm run build` produces `dist/` for any static host or Nginx next to `app/`, `api_server/`, and `libs/`.

Copy `.env.example` to `.env` if you need custom ports or proxy targets. **Do not commit** `.env`.

A gitignored `custom/` directory is available for your own deploy scripts.

## Security

This repository is a **proof of concept**: educational and demonstrative, **not** audited or intended for production use. Before any real deployment you would need at least:

Done so far, following QSLP/1:

- **Mutually authenticated exchange.** Both sides hold a long-lived ML-DSA-65
  identity and sign the handshake transcript, so neither the ephemeral key nor
  the answer can be substituted in transit (§7.2, §7.3).
- **No ephemeral key material at rest.** Key pairs are ephemeral, the shared
  secret lives only in the ephemeral store, and nothing is written to disk
  (§15.4). The signing identities *are* on disk, with `0600`, because an
  identity is long-lived by definition (§5.2) — that is the opposite case, not
  an exception.
- **No secrets in logs or responses** (§15.2, §15.3). Responses carry a
  fingerprint; the log redacts by whitelist, so a field added later cannot leak
  by omission.
- **Session identifiers are derived, not accepted** from the client (§7.4).

Still missing, and it is a long list:

1. **Certificates and revocation.** Identities are raw keys pinned on first
   use, so the *first* exchange is unauthenticated and a changed identity can
   only be refused, never explained. A real deployment needs a CA, a
   transparency log and revocation (§5.3, §5.4, §12).
2. **The hybrid suite.** This is ML-KEM and ML-DSA alone; QSLP/1 requires them
   paired with their classical equivalents, so that a break in either one is
   survivable (§4.1).
3. **Non-repudiation records**: signed receipts, timestamps and anchoring
   (§11). Signing the handshake proves who you are talking to; it does not yet
   prove what was said.
4. **HTTPS** everywhere, and CORS that is not `*`.
5. Rate limiting and anti-replay on the message layer.


## Contributing

Development workflow, branching model and pull request rules:
[CONTRIBUTING.md](CONTRIBUTING.md). Code style and file formatting:
[docs/guia-de-estilo.md](docs/guia-de-estilo.md). Security policy:
[SECURITY.md](SECURITY.md).

Both documents are written in Spanish, which is the working language of the
project. Quick start:

```bash
composer install && npm install
composer verificar    # syntax, style and static analysis
npm run formato       # front-end formatting

docker compose up -d --build
./scripts/prueba-e2e.sh    # end-to-end check against the running stack
```

`scripts/prueba-e2e.sh` walks the whole flow and then checks what must **fail**:
reusing an ephemeral key pair, inventing a session identifier, omitting it, and
finding key material on disk or in the log. A happy path that passes says
nothing about whether the defences are in place.

The protocol itself is defined by the reference implementation,
[ip5-kyber-poc](https://github.com/IP5-International-Platform-5/ip5-kyber-poc);
this repository follows it.
