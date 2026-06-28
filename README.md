# Kyber Post-Quantum Cryptography PoC

Key exchange and message encryption using **Kyber** (ML-KEM / post-quantum cryptography), exposed as a PHP API with an interactive web demo.

> **Proof of concept.** This repository illustrates a Kyber-based key exchange and message flow for learning and experimentation. It is **not** a hardened product: there is no authentication on the APIs, shared secrets may appear in responses for the demo, keys live on disk in plain folders, and many operational concerns are out of scope. **Do not** deploy it as-is for real users or sensitive data. See [Security](#security).



## Table of contents

- [Installation](#installation)
- [Architecture](#architecture)
- [API (endpoints)](#api-endpoints)
- [Communication flow](#communication-flow)
- [Demo](#demo)
- [Development](#development)
- [Security](#security)



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

