# Linux setup (Debian / Ubuntu)

Install and run this PoC on Linux with PHP and the **oqsphp** extension. For Docker, see [SETUP-DOCKER.md](SETUP-DOCKER.md).

Layout: static front under `dist/`, user app backend at `/app`, Kyber server API at `/api_server`, shared crypto in `libs/`.

## 1. System packages

PHP 8.x and a build toolchain for **liboqs-php** (submodule):

```bash
sudo apt update
sudo apt install -y \
  git cmake ninja-build gcc g++ swig pkg-config libssl-dev \
  php-cli php-fpm php-dev php-xml php-curl \
  nodejs npm
```

Check versions (`php -v`, `node -v`). Rebuild **oqsphp** whenever you upgrade PHP. Use the same PHP minor for CLI (`php -S`) and FPM (Nginx) if you run both.

## 2. Clone and submodules

```bash
git clone --recursive <repo-url> kyber
cd kyber
```

If the repo is already cloned without submodules:

```bash
git submodule update --init --recursive
```

## 3. Build and enable **oqsphp**

```bash
cd liboqs-php
./build.sh
cd ..
```

Extension artifact: `liboqs-php/build/oqsphp.so`.

Enable it in **both** CLI and FPM `php.ini` if you use the built-in server and Nginx (paths depend on your PHP minor version):

```bash
php --ini   # shows loaded ini files
```

Example (adjust `8.4` to your version):

```ini
extension=/absolute/path/to/kyber/liboqs-php/build/oqsphp.so
```

Add that line to `/etc/php/8.4/cli/php.ini` and, if using FPM, `/etc/php/8.4/fpm/php.ini`, then:

```bash
sudo systemctl restart php8.4-fpm   # only when using FPM
```

Verify:

```bash
php -m | grep oqsphp
php -r 'var_dump(extension_loaded("oqsphp"));'
```

## 4. Node dependencies and writable paths

```bash
npm ci
mkdir -p app/keys api_server/keys logs
chmod 770 app/keys api_server/keys logs
```

`app/keys/` and `api_server/keys/` hold Kyber material and shared secrets for the demo; `logs/requests.log` is appended by both backends.

Optional:

```bash
cp .env.example .env
```

Only needed if you change Vite/proxy ports (`VITE_SERVER_PORT`, etc.).

## 5. Run — development (recommended)

Two processes: PHP serves the API; Vite serves the front and proxies `/app` and `/api_server` to PHP (see `vite.config.js`).

**One command** (from repo root):

```bash
chmod +x run-full.sh
./run-full.sh
```

This starts `php -S 0.0.0.0:8000` on the repo root and Vite on **5173**. Open **http://localhost:5173** (demo at `/demo`). Edit front or PHP under `app/`, `api_server/`, or `libs/` and refresh with **F5**.

**Manual equivalent:**

```bash
# terminal 1 — API (document root = repo root; Vite requests …/app/foo.php and …/api_server/foo.php)
php -S 0.0.0.0:8000

# terminal 2
VITE_SERVER_PORT=8000 npm run dev
```

The built-in server does **not** read `.htaccess`; routing works because the Vite proxy rewrites to `*.php` paths that exist on disk.

## 6. Run — Nginx + PHP-FPM

Build the front once:

```bash
npm run build
```

Install Nginx if needed: `sudo apt install nginx`.

Example site config — replace `/var/www/kyber` with your clone path and `php8.4-fpm.sock` with your FPM socket:

```nginx
upstream kyber_php {
    server unix:/run/php/php8.4-fpm.sock;
}

server {
    listen 80;
    server_name localhost;
    client_max_body_size 2m;
    root /var/www/kyber/dist;

    location ~ ^/app/(?<endpoint>[^/]+)/?$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/kyber/app/$endpoint.php;
        fastcgi_param SCRIPT_NAME /app/$endpoint.php;
        fastcgi_pass kyber_php;
    }

    location ~ ^/api_server/(?<endpoint>[^/]+)/?$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/kyber/api_server/$endpoint.php;
        fastcgi_param SCRIPT_NAME /api_server/$endpoint.php;
        fastcgi_pass kyber_php;
    }

    location = /demo {
        rewrite ^ /demo.html last;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Enable the site, test, reload Nginx. Open **http://localhost/** (port 80).

Alternatively, `npm run preview` serves `dist/` on **4173** with the same API proxy as dev if PHP is already listening on the port in `vite.config.js` (default **8000**).

## 7. Smoke test

```bash
curl -s http://localhost:8000/api_server/get_public_key | jq .
# or, with Nginx on port 80:
curl -s http://localhost/api_server/get_public_key | jq .
```

Then walk through **http://localhost:5173/demo** (dev) or **/demo** (Nginx).

## Troubleshooting

| Symptom | What to check |
|--------|----------------|
| `oqsphp` missing in `php -m` | Rebuild after PHP upgrade; correct absolute path in the **same** `php.ini` as the SAPI you use (`php --ini`). |
| 404 on `/app/…` or `/api_server/…` with `php -S` | Use Vite dev/proxy or request `…/endpoint.php` directly; built-in server has no rewrite. |
| 404 with Nginx | `SCRIPT_FILENAME` paths, FPM socket, `fastcgi_pass`, file permissions on `app/` and `api_server/`. |
| Decrypt fails after retries | Stale `shared_secret.key` — delete `app/keys/shared_secret.key` and `api_server/keys/shared_secret.key`, rerun from “Get public key”. |
| Permission errors on keys/logs | Owner/group of the PHP process must write `app/keys`, `api_server/keys`, `logs`. |

## Notes

This repository is a **proof of concept**, not hardened for production. Use HTTPS and proper auth if you expose it beyond localhost.
