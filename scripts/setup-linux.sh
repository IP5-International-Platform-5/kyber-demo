#!/bin/bash
# Script de configuración inicial para entorno Linux

# Verificar que estamos en Linux y no en Windows
OS_TYPE=$(uname -s)
if [[ "$OS_TYPE" != "Linux" && "$OS_TYPE" != "Darwin" ]]; then
  echo -e "\033[0;31mError: Este script debe ejecutarse en Linux o macOS, no en Windows\033[0m"
  echo -e "\033[0;33mSugerencia: Usa Windows Subsystem for Linux (WSL) o una máquina virtual con Linux.\033[0m"
  exit 1
fi

echo -e "\033[0;32mSistema operativo compatible detectado: $OS_TYPE\033[0m"

# Asignar permisos de ejecución a todos los scripts
echo -e "\033[0;33mAsignando permisos de ejecución a scripts...\033[0m"
chmod +x *.sh
echo -e "\033[0;32mPermisos asignados correctamente\033[0m"

# Verificar requisitos mínimos
echo -e "\033[0;33mVerificando requisitos mínimos...\033[0m"

# Verificar PHP
if ! command -v php &> /dev/null; then
  echo -e "\033[0;31mPHP no está instalado. Por favor, instálalo antes de continuar.\033[0m"
  echo -e "\033[0;33mPuedes instalarlo con: sudo apt update && sudo apt install php php-cli php-curl php-xml\033[0m"
  exit 1
else
  PHP_VERSION=$(php -v | head -n 1 | cut -d' ' -f2)
  echo -e "\033[0;32mPHP $PHP_VERSION está instalado\033[0m"
fi

# Verificar Node.js
if ! command -v node &> /dev/null; then
  echo -e "\033[0;31mNode.js no está instalado. Por favor, instálalo antes de continuar.\033[0m"
  echo -e "\033[0;33mPuedes instalarlo con: curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs\033[0m"
  exit 1
else
  NODE_VERSION=$(node -v)
  echo -e "\033[0;32mNode.js $NODE_VERSION está instalado\033[0m"
fi

# Verificar npm
if ! command -v npm &> /dev/null; then
  echo -e "\033[0;31mnpm no está instalado. Por favor, instálalo antes de continuar.\033[0m"
  echo -e "\033[0;33mPuedes instalarlo con: sudo apt install npm\033[0m"
  exit 1
else
  NPM_VERSION=$(npm -v)
  echo -e "\033[0;32mnpm $NPM_VERSION está instalado\033[0m"
fi

# Instalar dependencias de npm si es necesario
if [ ! -d "node_modules" ]; then
  echo -e "\033[0;33mInstalando dependencias de Node.js...\033[0m"
  npm install
  if [ $? -ne 0 ]; then
    echo -e "\033[0;31mError al instalar las dependencias de Node.js.\033[0m"
    exit 1
  fi
  echo -e "\033[0;32mDependencias de Node.js instaladas correctamente\033[0m"
else
  echo -e "\033[0;32mDependencias de Node.js ya instaladas\033[0m"
fi

# Verificar si ya existe el archivo .env para la configuración de despliegue
if [ ! -f ".env" ]; then
  echo -e "\033[0;33mCreando archivo .env para configuración de despliegue...\033[0m"
  cat > .env << EOF
# Configuración de despliegue SFTP
VITE_SFTP_HOST=tu-servidor.com
VITE_SFTP_PORT=22
VITE_SFTP_USER=tu-usuario
VITE_SFTP_REMOTE_DIR=/ruta/en/servidor
EOF
  echo -e "\033[0;32mArchivo .env creado. Por favor, edita los valores según tu configuración.\033[0m"
else
  echo -e "\033[0;32mEl archivo .env ya existe\033[0m"
fi

echo -e "\033[0;32m✅ Configuración inicial completada. Ahora puedes ejecutar:\033[0m"
echo -e "\033[0;33m- ./run-full.sh para iniciar el proyecto completo\033[0m"
echo -e "\033[0;33m- ./generate-kyber-keys.sh para generar claves Kyber nuevas\033[0m"
echo -e "\033[0;33m- npm run deploy para desplegar en el servidor remoto\033[0m"