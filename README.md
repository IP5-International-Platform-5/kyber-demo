# Kyber Post-Quantum Cryptography PoC

Key exchange and message encryption using **ML-KEM-768** (FIPS 203, the standardised form of Kyber), exposed as a PHP API with an interactive web demo.

> **Proof of concept.** This repository illustrates a Kyber-based key exchange and message flow for learning and experimentation. It is **not** a hardened product: there is no authentication on the APIs, keys are persistent and live on disk in plain folders, and many operational concerns are out of scope. **Do not** deploy it as-is for real users or sensitive data. See [Security](#security).



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
| Node | 20 | `.nvmrc`, `engines` de `package.json` e imágenes por digest |
| Nginx | `alpine` | `docker/nginx/Dockerfile`, imagen fijada por digest |
| Algoritmo KEM | ML-KEM-768 (FIPS 203) | constante `KEM_ALG` en `libs/kyber_utils.php` |

### Qué hace falta en local

| Herramienta | Para qué | Instalación en Arch/Manjaro |
| ----------- | -------- | --------------------------- |
| Docker + Compose | Ejecutar la demo. Es lo único imprescindible | `sudo pacman -S docker docker-compose` |
| PHP 8.x | `php -l` y las herramientas de estilo. **No ejecuta la demo** | `sudo pacman -S php` |
| Composer | Dependencias de desarrollo | `sudo pacman -S composer` |
| Node 20 | Solo si tocas el front fuera del contenedor | `nvm use` |

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
- **Node 20 llegó a su fin de vida el 30 de abril de 2026** y ya no recibe
  parches de seguridad. Las imágenes fijadas aquí son de abril de 2026, que es
  exactamente cuando dejaron de reconstruirse. Están fijadas para que la
  compilación sea reproducible, no porque sean las adecuadas: hay que subir a
  Node 24, que es la LTS activa. Vite 6 lo admite, así que el cambio es
  acotado, pero toca la compilación del front y merece su propio commit.

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


Each backend has its own `config.php` and `cors_headers.php`. Keys: `app/keys/` (app side) and `api_server/keys/` (server). In a real deployment these would be different hosts; here they are two folders on one machine. After Kyber, each side stores its own copy of the shared secret on disk (the **value** must match). If steps get out of order, start again from “get public key” or delete `shared_secret.key` in both key directories.

The `demo.html` page groups calls that would normally go to `app` and `api_server` separately.

## API (endpoints)



### 1. Get public key

- **URL:** `/api_server/get_public_key`
- **Method:** GET
- **Response:** JSON with the public key in **base64** (Kyber bytes).



### 2. Create shared secret

- **URL:** `/app/get_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "public_key": "server_public_key_base64"
  }
  ```
- **Response:** `ciphertext` in **base64** and `secret_fingerprint`. The shared secret itself never leaves the backend.



### 3. Send shared secret

- **URL:** `/api_server/set_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "ciphertext": "kyber_ciphertext_base64"
  }
  ```
- **Response:** Decapsulation result: `secret_fingerprint`, which must match the one reported by the app side.



### 4. Encrypt message

- **URL:** `/app/encrypt_message`
- **Method:** POST
- **Body:**
  ```json
  {
    "message": "plaintext_message"
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
    "tag": "base64_auth_tag"
  }
  ```
- **Response:** `message` field (plaintext).



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

1. Authentication and authorization on endpoints.
2. **HTTPS** everywhere.
3. Proper protection for keys at rest.
4. Key rotation policies.

