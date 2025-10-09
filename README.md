# API para Kyber Post-Quantum Cryptography

Esta API implementa un sistema basado en Kyber (algoritmo post-cuántico) para intercambio de claves y cifrado de mensajes.

## Requisitos

- PHP 7.4 o superior
- Extensión libOQS-php instalada (ver sección de instalación)
- Extensión OpenSSL para PHP
- Node.js para el despliegue y desarrollo frontend
- Git

## Instalación

### 1. Clonar el repositorio

Este proyecto utiliza git submodules para la librería libOQS-php. Clona el repositorio con:

```bash
git clone --recursive https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO
```

Si ya clonaste el repositorio sin el flag `--recursive`, inicializa los submodules con:

```bash
git submodule update --init --recursive
```

### 2. Compilar libOQS-php

1. Instala las dependencias necesarias:
```bash
sudo apt install -y cmake gcc ninja-build swig php-dev
```

2. Entra al directorio y ejecuta el script de compilación:
```bash
cd liboqs-php
./build.sh
```

3. Agrega la extensión a tu archivo php.ini:
```
extension=/ruta/completa/a/liboqs-php/build/oqsphp.so
```

4. Reinicia tu servidor web.

### 3. Configurar variables de entorno

1. Copia el archivo `.env.example` a `.env`:
```bash
cp .env.example .env
```

2. Edita el archivo `.env` con tus credenciales de despliegue SFTP (si aplica).

## Estructura del API

La API proporciona los siguientes endpoints:

### 1. Obtener clave pública
- **URL**: `/api_server/get_public_key`
- **Método**: GET
- **Respuesta**: JSON con la clave pública del servidor en formato hexadecimal.

### 2. Generar clave compartida
- **URL**: `/api_client/get_shared_secret`
- **Método**: POST
- **Cuerpo de la petición**:
  ```json
  {
    "public_key": "clave_pública_en_hexadecimal"
  }
  ```
- **Respuesta**: JSON con la clave compartida en formato hexadecimal y el ciphertext.

### 3. Enviar clave compartida
- **URL**: `/api_server/set_shared_secret`
- **Método**: POST
- **Cuerpo de la petición**:
  ```json
  {
    "ciphertext": "texto_cifrado_en_hexadecimal"
  }
  ```
- **Respuesta**: JSON con información sobre el proceso de descapsulación.

### 4. Cifrar mensaje
- **URL**: `/api_client/encrypt_message`
- **Método**: POST
- **Cuerpo de la petición**:
  ```json
  {
    "message": "mensaje_a_cifrar"
  }
  ```
- **Respuesta**: JSON con los datos cifrados y el vector de inicialización.

### 5. Descifrar mensaje
- **URL**: `/api_server/decrypt_message`
- **Método**: POST
- **Cuerpo de la petición**:
  ```json
  {
    "encrypted_data": "datos_cifrados_en_hexadecimal",
    "iv": "vector_de_inicializacion_en_hexadecimal"
  }
  ```
- **Respuesta**: JSON con el mensaje descifrado.

## Flujo de comunicación

1. El cliente solicita la clave pública al servidor mediante `/api_server/get_public_key`.
2. El cliente utiliza la clave pública para encapsular una clave secreta compartida mediante `/api_client/get_shared_secret`.
3. El cliente envía el ciphertext al servidor mediante `/api_server/set_shared_secret`.
4. El servidor usa su clave privada para extraer la clave secreta compartida.
5. Para las comunicaciones subsiguientes, el cliente cifra los mensajes usando la clave compartida mediante `/api_client/encrypt_message`.
6. El servidor descifra los mensajes recibidos del cliente mediante `/api_server/decrypt_message`.

## Demo de Cliente

Se incluye un archivo de demostración `demo.html` que muestra cómo un cliente web podría interactuar con esta API:

- Obtiene la clave pública del servidor
- Simula la encapsulación de una clave compartida
- Cifra y envía mensajes usando la clave compartida

Nota: La demo simula el proceso de encapsulación de Kyber en el cliente, ya que aún no existen implementaciones en JavaScript. En un caso real, se podría usar WebAssembly con una implementación de Kyber compilada.

## Desarrollo y Despliegue

### Comandos de desarrollo

- `npm run dev` - Inicia el servidor de desarrollo de Vite
- `npm run build` - Construye la aplicación para producción
- `npm run preview` - Previsualiza la versión compilada localmente

### Despliegue SFTP

El proyecto está configurado para desplegarse mediante SFTP (SSH File Transfer Protocol). Para configurar el despliegue:

1. Crea un archivo `.env` en la raíz del proyecto con la siguiente estructura:
   ```
   # Configuración SFTP
   VITE_SFTP_HOST=ssh.tudominio.com
   VITE_SFTP_PORT=22
   VITE_SFTP_USER=tu_usuario_ssh
   VITE_SFTP_REMOTE_DIR=/ruta/en/el/servidor/
   # Solo si tu clave privada tiene passphrase:
   # VITE_SFTP_KEY_PASSPHRASE=tu-passphrase
   ```

2. Asegúrate de que el archivo `.env` esté incluido en `.gitignore` para no exponer tus credenciales.

3. Para una mayor seguridad, configura la autenticación con clave SSH:
   ```bash
   # Genera un par de claves SSH si aún no tienes uno
   ssh-keygen -t rsa -b 4096 -C "tu-email@ejemplo.com"

   # Sube la clave pública (.pub) a tu servidor
   # Coloca la clave privada en el directorio keys/ del proyecto como aws-kyber.pem
   ```

4. Si tienes una clave en formato PPK (PuTTY), conviértela a PEM:
   ```bash
   npm run convert-key
   ```

5. Comandos de despliegue disponibles:
   - `npm run build` - Construye la aplicación para producción en la carpeta `dist/`
   - `npm run deploy` - Construye la aplicación y la despliega automáticamente usando SFTP

### Solución de problemas en el despliegue

#### Problemas comunes con SFTP
- Asegúrate de que el servicio SSH esté activo en el servidor
- Verifica que el puerto SSH (generalmente 22) esté abierto y accesible
- Comprueba los permisos de escritura en la carpeta de destino
- Si usas autenticación por clave, asegúrate de que la clave pública esté correctamente instalada en el servidor

#### Errores comunes
- **Error de permiso denegado**: Asegúrate de que la clave SSH tiene los permisos correctos (600 en sistemas Unix)
- **Error de host no encontrado**: Verifica la dirección del servidor en el archivo `.env`
- **Error de autenticación**: Comprueba que el usuario y la clave son correctos

### Consideraciones de seguridad en el despliegue
- Toda la comunicación SFTP está cifrada
- Nunca compartas tu archivo `.env` o tus claves privadas
- Crea un usuario específico para el despliegue con acceso limitado solo a los directorios necesarios
- Usa autenticación por clave SSH en lugar de contraseña para mayor seguridad
- Considera usar una passphrase para tu clave privada SSH

## Nota importante sobre seguridad

Este código es para fines educativos y demostrativos. Para un entorno de producción:

1. Implementa autenticación adecuada para tus endpoints
2. Usa HTTPS para todas las comunicaciones
3. Considera usar mecanismos adicionales de protección para las claves almacenadas
4. Implementa políticas de rotación de claves