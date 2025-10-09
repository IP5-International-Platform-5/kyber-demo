# Configuración para desarrollo local

Este documento explica cómo configurar y ejecutar el proyecto Kyber en un entorno de desarrollo local.

## Requisitos previos

Para ejecutar este proyecto completo necesitarás:

1. **Node.js y npm** - Para el frontend y herramientas de construcción
2. **PHP 7.4 o superior** - Para la API backend
3. **Servidor web (Apache o Nginx)** - Para servir los archivos PHP
4. **Extensión libOQS-php** - Para la criptografía post-cuántica

## Configuración del entorno

### 1. Instalar XAMPP (o similar)

La forma más sencilla de configurar el entorno PHP es instalando XAMPP:

1. Descarga XAMPP desde [https://www.apachefriends.org/es/index.html](https://www.apachefriends.org/es/index.html)
2. Instala XAMPP con los componentes Apache y PHP (MySQL es opcional)
3. Inicia los servicios de Apache desde el panel de control de XAMPP

### 2. Instalar la extensión libOQS-php

Para instalar la extensión libOQS-php:

1. Asegúrate de que tienes instaladas las herramientas de compilación necesarias (Visual Studio Build Tools en Windows o gcc en Linux)
2. Ejecuta el script de compilación en el directorio `liboqs-php`:
   ```
   cd liboqs-php
   ./build.sh
   ```
3. Copia el archivo `.so` o `.dll` generado al directorio de extensiones de PHP
4. Edita tu `php.ini` para cargar la extensión:
   ```
   extension=ruta/completa/a/oqsphp.so
   ```
5. Reinicia el servidor Apache

### 3. Configuración del proyecto

#### Frontend (Vite)

1. Instala las dependencias del proyecto:
   ```
   npm install
   ```

2. Inicia el servidor de desarrollo:
   ```
   npm run dev
   ```

#### Backend (PHP)

1. Configura tu servidor web para que el directorio raíz apunte a este proyecto

2. Asegúrate de que la carpeta `api/keys` tenga permisos de escritura:
   ```
   chmod 700 api/keys  # En sistemas Unix
   ```

## Ejecución del proyecto

### Método 1: Desarrollo con servidores separados

1. Inicia tu servidor web (Apache/XAMPP) para el backend PHP
2. En otra terminal, inicia el servidor de Vite para el frontend:
   ```
   npm run dev
   ```
3. Accede a `http://localhost:5173` para ver la aplicación

Con esta configuración, las peticiones a `/api/*` serán redirigidas automáticamente al servidor PHP gracias al proxy configurado en `vite.config.js`.

### Método 2: Usando solo el servidor web

1. Construye la aplicación frontend:
   ```
   npm run build
   ```
2. Copia todo el contenido de la carpeta `dist` a la carpeta pública de tu servidor web (ej: `htdocs/kyber`)
3. Copia también la carpeta `api` a la misma ubicación
4. Accede a tu servidor web (ej: `http://localhost/kyber`)

## Solución de problemas

### Problemas comunes en Windows

- **Extensión libOQS-php no funciona**: Asegúrate de que estás usando la versión correcta de PHP y que la extensión es compatible.
- **Permisos de archivos**: En Windows, puede que necesites ajustar los permisos de la carpeta `api/keys`.
- **Error 404 en API**: Verifica que las rutas de redirección estén correctamente configuradas en Apache o en el proxy de Vite.

### Verificación de la instalación

Para verificar que la extensión libOQS-php está correctamente instalada, crea un archivo `test.php` con el siguiente contenido:

```php
<?php
phpinfo();
```

Accede a este archivo desde el navegador y busca "oqsphp" en la lista de extensiones.

## Notas adicionales

- En entornos de producción, es recomendable utilizar HTTPS para todas las comunicaciones.
- La API actual está diseñada para fines de demostración. En un entorno real, deberías implementar mecanismos de autenticación y autorización adecuados.
