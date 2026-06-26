# Docker setup

Run the PoC with **Docker Compose**. For native Linux (Debian/Ubuntu), see [SETUP-LINUX.md](SETUP-LINUX.md).

You do not need PHP, **liboqs-php**, or Node on the host to try the app: the **php** image ships the **oqsphp** extension, and the **web** image builds the Vite front during the image build.

## Requirements

You do **not** need PHP, **liboqs-php**, or Node on the host to open **[http://localhost:8080](http://localhost:8080)** — only to run the optional `npm run docker:`* shortcuts (you can use `docker compose` directly instead).

### Linux


| Requirement                        | Notes                                                                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Docker Engine** + **Compose v2** | e.g. `docker.io` + `docker-compose-v2` on Debian/Ubuntu, or Docker CE from your distro.                                           |
| **Git**                            | Submodule `liboqs-php` must be present after clone.                                                                               |
| **RAM / disk**                     | First **php** image build compiles libOQS inside the container; allow several GB free disk and ~4 GB RAM for Docker during build. |
| **Ports**                          | **8080** (app) free; **5173** only if you use the `dev` profile.                                                                  |


Check:

```bash
docker compose version
git --version
```



### Windows


| Requirement                                                           | Notes                                                                                                             |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** | Use the **WSL 2** backend (default on current installs).                                                          |
| **WSL 2**                                                             | A Linux distro in WSL (e.g. Ubuntu) is recommended for running `docker compose` and Git.                          |
| **Git**                                                               | [Git for Windows](https://git-scm.com/) or Git inside WSL; clone with `--recursive` or init submodules afterward. |
| **Project path**                                                      | Prefer cloning inside the WSL filesystem (e.g. `~/kyber`), not under `C:\`, for faster volume mounts.             |
| **Docker Desktop resources**                                          | In Settings → Resources, allocate enough **memory** (6–8 GB helps the first **php** build) and disk.              |
| **Ports**                                                             | **8080** and **5173** (dev profile) must not be used by another app.                                              |


Check in PowerShell or WSL:

```bash
docker compose version
git --version
```

Open the demo in a browser at **[http://localhost:8080/demo](http://localhost:8080/demo)** (same URL on Linux and Windows).

### Common (both platforms)

- **Git submodule:** `liboqs-php` (required for the **php** image build).
- **Optional:** Node.js + npm only if you use `npm run docker:up` / `docker:dev`; otherwise run `docker compose` from the repo root.



## 1. Clone

```bash
git clone --recursive <repo-url> kyber
cd kyber
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```



## 2. Start the stack

The **first** `up --build` compiles libOQS inside the **php** image and runs `npm ci` + Vite in **web**.

From the repo root:

```bash
docker compose up --build
```

Or in the background:

```bash
npm run docker:up
```

Open **[http://localhost:8080](http://localhost:8080)** — demo at `/demo` or `/demo.html`.

## Services


| Service | Role                                                                                                                   |
| ------- | ---------------------------------------------------------------------------------------------------------------------- |
| **php** | `php:8.4-fpm-bookworm` with **oqsphp** (libOQS + `liboqs-php` compiled in the image). Repo mounted at `/var/www/html`. |
| **web** | Nginx serves the built `dist/` and forwards `/app` and `/api_server` to PHP-FPM.                                       |


Definitions: `docker-compose.yml`, `docker/php/Dockerfile`, `docker/nginx/Dockerfile`, `docker/nginx/default.conf`.

## Ports


| Port     | Use                                                            |
| -------- | -------------------------------------------------------------- |
| **8080** | App via Nginx (static front from the image build).             |
| **5173** | Vite dev server only when using the `dev` profile (see below). |




## Hot-reload front (`dev` profile)

To edit `src/`, `index.html`, or `demo.html` without rebuilding the **web** image:

```bash
npm run docker:dev
```

Open **[http://localhost:5173](http://localhost:5173)** (not 8080). Vite proxies `/app` and `/api_server` to the **web** container; PHP code is still served from the mounted repo via **php**.

## npm scripts


| Command                | Description                            |
| ---------------------- | -------------------------------------- |
| `npm run docker:build` | `docker compose build`                 |
| `npm run docker:up`    | `docker compose up --build -d`         |
| `npm run docker:dev`   | Stack + **dev** profile (Vite on 5173) |




## Notes

- The **first** build of **php** can take a long time (compiles libOQS).
- The **web** image runs `npm ci` and `vite build` during build; you do not need `npm install` on the host just to open 8080.
- The **dev** profile uses `node:20-alpine`. If image pull seems stuck, wait or run `docker pull node:20-alpine` in another terminal.
- Keys and logs persist on the host through the **php** volume: `app/keys/`, `api_server/keys/`, `logs/`.
- After changes only to static front files baked into **web**, rebuild: `docker compose build web` or `docker compose up --build`.



## Smoke test

```bash
curl -s http://localhost:8080/api_server/get_public_key | jq .
```

Then open **[http://localhost:8080/demo](http://localhost:8080/demo)**.

## Troubleshooting


| Symptom                   | What to check                                                                                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Build fails on **php**    | Submodule `liboqs-php` present; enough disk/RAM for libOQS compile. On Windows, increase Docker Desktop memory or clone under WSL. |
| Slow mounts / file sync   | On Windows, move the repo from `C:\` into WSL (`\\wsl$\…` or clone in `~`).                                                        |
| 8080 connection refused   | `docker compose ps`; **web** container up and port not in use.                                                                     |
| API 502 / empty response  | **php** container running; logs: `docker compose logs php`.                                                                        |
| Decrypt fails in demo     | Stale `shared_secret.key` in `app/keys` and `api_server/keys` — delete both and rerun from step 1.                                 |
| Front changes not on 8080 | Rebuild **web** or use `docker:dev` on 5173.                                                                                       |


