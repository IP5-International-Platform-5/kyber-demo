# Kyber Post-Quantum Cryptography API

Key exchange and message encryption using **Kyber** (ML-KEM / post-quantum cryptography), exposed as a PHP API with a web demo.

## Table of contents

- [Quick start with Docker](#quick-start-docker)
- [Front, user app backend, and Kyber server](#front-app-and-server)
- [Requirements](#requirements)
- [Local install without Docker](#local-install)
- [API (endpoints)](#api-endpoints)
- [Communication flow](#flow)
- [Demo](#demo)
- [Development and deployment](#development)
- [Security](#security)

<a id="quick-start-docker"></a>

## Quick start with Docker

You do not need PHP or a local **liboqs-php** build: the backend runs in an image with the **oqsphp** extension, and the frontend is built inside the Nginx image (`docker/php`, `docker/nginx`).

| Service | Role |
|---------|------|
| **php** | `php:8.4-fpm-bookworm`, compiled extension (libOQS + `liboqs-php`). Mounts the repo at `/var/www/html`. |
| **web** | Nginx serving the built `dist/`. You do not need `npm install` on your machine just to try the app. |

### Steps

1. Clone with submodules: `git clone --recursive <repo-url>` (if you already cloned without them: `git submodule update --init --recursive`).
2. From the repo root: `docker compose up --build` (or `npm run docker:up`).
3. Open **http://localhost:8080** — the demo is at **`/demo`** or **`/demo.html`**.

### Ports

| Port | Use |
|------|-----|
| **8080** | App served by Nginx (static front from the build; production-like). |
| **5173** | Only when using the **dev** profile (Vite with hot reload). |

### Hot-reload front ( **`dev`** profile )

To edit `src/`, `index.html`, or `demo.html` without rebuilding the `web` image:

```bash
npm run docker:dev
```

Open **http://localhost:5173** (not 8080 for this). Vite proxies `/app` (user app backend) and `/api_server` to the Nginx container; PHP stays mounted from the repo.

### Docker notes

- The **first** **php** image build can take a long time (compiles libOQS). The **web** image runs `npm ci` and `vite build` during build.
- The **`dev`** profile uses the official **`node:20-alpine`** image (small). The first time, Docker downloads it; if the “Pulling” bar looks stuck, it is often a slow network or large layers: wait, or run `docker pull node:20-alpine` in a terminal to see per-layer progress.
- Keys and logs on your disk via the **php** service volume: `app/keys/` (user app), `api_server/keys/` (Kyber server), `logs/` (in a real deployment these would be different hosts; here they are simulated with two folders).
- If you only change the **static** front baked into the `web` image, rebuild: `docker compose build web` or `docker compose up --build`.

<a id="front-app-and-server"></a>

## Front, user app backend, and Kyber server

The **browser** is the front end. The **user application backend** (`app/`) holds routes such as encapsulation and AES encryption—what you would deploy next to your static site or SPA. The **Kyber server API** (`api_server/`) exposes the server public key, decapsulation, and decrypt. Shared crypto code lives under **`api/`** (e.g. `kyber_utils.php`, CORS).

Keys: `app/keys/` for the app side and `api_server/keys/` for the server. In production these directories would live on different machines; locally or in Docker they are **simulated** with two folders. If you still have keys under the old `api_client/keys/` path, move them to `app/keys/`. After Kyber, each side keeps its own copy of the shared secret on disk (the **value** must match). If you get the steps out of order, start again from “public key” or delete those `shared_secret.key` files / key folders.

The **`demo.html`** callout explains that one page only groups HTTP calls that would normally go to the app backend and to the server API separately.

<a id="requirements"></a>

## Requirements

- **PHP 7.4+** for a local install (the Docker backend image uses **PHP 8.4** with the extension prebuilt).
- **libOQS-php** locally (see install); with Docker you do not need it on the host.
- **OpenSSL** for PHP.
- **Node.js** only if you build the front on your machine or use `npm run dev` / `docker:dev`.
- **Git**

<a id="local-install"></a>

## Local install without Docker

You need PHP with **oqsphp** and Node for the front. See [SETUP-LOCAL.md](SETUP-LOCAL.md) for a practical guide (e.g. XAMPP).

### 1. Clone the repository

This project uses the **liboqs-php** submodule:

```bash
git clone --recursive https://github.com/YOUR_USER/YOUR_REPO.git
cd YOUR_REPO
```

If you cloned without `--recursive`:

```bash
git submodule update --init --recursive
```

### 2. Build libOQS-php

1. Dependencies (Debian/Ubuntu example):

```bash
sudo apt install -y cmake gcc ninja-build swig php-dev
```

2. Build:

```bash
cd liboqs-php
./build.sh
```

3. In `php.ini`:

```
extension=/full/path/to/liboqs-php/build/oqsphp.so
```

4. Restart the web server if applicable.

### 3. Environment variables (optional)

```bash
cp .env.example .env
```

Edit `.env` if you need variables (e.g. `VITE_SERVER_PORT` with local Vite). Not required to try Docker.

<a id="api-endpoints"></a>

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

- **Response:** `ciphertext` and `shared_secret` in **base64** (plaintext secret in the response is for demos only).

### 3. Send shared secret

- **URL:** `/api_server/set_shared_secret`
- **Method:** POST
- **Body:**

  ```json
  {
    "ciphertext": "kyber_ciphertext_base64"
  }
  ```

- **Response:** Decapsulation result (e.g. `shared_secret` in base64).

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

<a id="flow"></a>

## Communication flow

1. Front requests the public key: `/api_server/get_public_key`.
2. User app backend encapsulates via `/app/get_shared_secret`.
3. Front sends the ciphertext: `/api_server/set_shared_secret`.
4. Server decapsulates with its private key and derives the same shared secret.
5. User app backend encrypts messages: `/app/encrypt_message`.
6. Server decrypts: `/api_server/decrypt_message`.

<a id="demo"></a>

## Demo

The **`demo.html`** page walks through the flow by calling the backends. The browser **does not** run Kyber in JavaScript: post-quantum work is done by **PHP** in `app/` (user app) and `api_server/` (Kyber server).

- Fetches the server public key.
- Agrees the shared secret via the API (Kyber on the server).
- Encrypts and decrypts with AES-GCM using that secret.

A 100% browser-only front would need WebAssembly or another Kyber module; here encapsulation and encrypt live in **`app/`** as the user backend, separate from **`api_server/`** on a real network.

<a id="development"></a>

## Development and deployment

### Useful commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Vite dev server (local, proxies to PHP). |
| `npm run build` | Writes `dist/`. |
| `npm run preview` | Previews `dist/` (API proxy in `vite.config.js`). |
| `npm run docker:up` | `docker compose up --build` (Nginx + PHP; `dist` is produced in the image build). |
| `npm run docker:dev` | Docker stack + Vite on **5173** (`dev` profile, hot reload for the front). |

### Front deployment

`npm run build` outputs static assets under **`dist/`**, ready for any static host or Nginx/Apache next to `app/`, `api_server/`, `api/`, etc.

### Environment variables

Copy `.env.example` to `.env` and adjust as needed. **Do not commit `.env`.**

### Custom deployment

You can use a `custom/` directory (gitignored) for your own scripts (SFTP, rsync, etc.).

<a id="security"></a>

## Security

This repository is **educational and demonstrative**. For production:

1. Authentication and authorization on endpoints.
2. **HTTPS** everywhere.
3. Proper protection for keys at rest.
4. Key rotation policies.
