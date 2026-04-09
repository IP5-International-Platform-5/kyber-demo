# Local development setup

How to configure and run the Kyber project on your machine without Docker.

## Prerequisites

1. **Node.js and npm** — frontend and build tools  
2. **PHP 7.4 or newer** — backend API  
3. **Web server (Apache or Nginx)** — to serve PHP  
4. **libOQS-php extension** — post-quantum crypto  

## Environment setup

### 1. Install XAMPP (or similar)

A simple way to get PHP + Apache:

1. Download XAMPP from [https://www.apachefriends.org/](https://www.apachefriends.org/)
2. Install with Apache and PHP (MySQL optional)
3. Start Apache from the XAMPP control panel

### 2. Install the libOQS-php extension

1. Install a C/C++ toolchain (Visual Studio Build Tools on Windows, or gcc on Linux)
2. In the `liboqs-php` directory, run the build script:
   ```
   cd liboqs-php
   ./build.sh
   ```
3. Copy the generated `.so` or `.dll` into your PHP extensions directory
4. Enable it in `php.ini`:
   ```
   extension=/full/path/to/oqsphp.so
   ```
5. Restart Apache

### 3. Project configuration

#### Frontend (Vite)

1. Install dependencies:
   ```
   npm install
   ```

2. Start the dev server:
   ```
   npm run dev
   ```

#### Backend (PHP)

1. Point your web server document root at this project (or a virtual host).

2. Ensure `app/keys` and `api_server/keys` are writable:
   ```
   chmod 700 app/keys api_server/keys   # Unix
   ```

## Running the project

### Option A: Separate dev servers

1. Start your web server (Apache/XAMPP) for PHP  
2. In another terminal, run Vite:
   ```
   npm run dev
   ```
3. Open `http://localhost:5173`

Requests to `/app` and `/api_server` are proxied to PHP via `vite.config.js`.

### Option B: Web server only

1. Build the frontend:
   ```
   npm run build
   ```
2. Copy `dist/` into your web root (e.g. `htdocs/kyber`)
3. Copy `api/`, `app/`, `api_server/`, etc. as needed for your layout
4. Open your site (e.g. `http://localhost/kyber`)

## Troubleshooting

### Common issues on Windows

- **libOQS-php not loading**: Match PHP version to the built extension and check `php.ini`.
- **File permissions**: You may need to adjust permissions on `app/keys` and `api_server/keys`.
- **API 404**: Check Apache/Nginx rewrites and the Vite dev proxy.

### Verifying the extension

Create `test.php`:

```php
<?php
phpinfo();
```

Open it in the browser and search for `oqsphp` in the extensions list.

## Additional notes

- Use HTTPS in production.
- This API is for demonstration; add real authentication and authorization for production use.
