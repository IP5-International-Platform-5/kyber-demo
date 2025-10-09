#!/bin/bash
# Script para ejecutar todo el proyecto Kyber en entorno Linux (frontend y backend)

# Verificar que estamos en Linux y no en Windows
if [ -f "./check-linux.sh" ]; then
  source ./check-linux.sh
  if [ $? -ne 0 ]; then
    exit 1
  fi
else
  # Verificación rápida si el script check-linux.sh no existe
  OS_TYPE=$(uname -s)
  if [[ "$OS_TYPE" != "Linux" && "$OS_TYPE" != "Darwin" ]]; then
    echo -e "\033[0;31mError: Este script debe ejecutarse en Linux o macOS, no en Windows\033[0m"
    exit 1
  fi
fi

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
API_PORT=8000
VITE_PORT=5173
API_DIR="$(pwd)/api"
PROJECT_ROOT="$(pwd)"
LOG_FILE="$PROJECT_ROOT/app-run.log"

# Función para verificar si un comando está disponible
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}$1 no está instalado. Ejecuta:${NC}"
        echo -e "$2"
        return 1
    else
        echo -e "${GREEN}✓ $1 está instalado${NC}"
        return 0
    fi
}

# Verificar dependencias
echo -e "${YELLOW}Verificando dependencias...${NC}"

# Verificar PHP
check_command php "sudo apt update && sudo apt install php php-cli php-curl php-xml"
PHP_OK=$?

# Verificar Node.js y npm
check_command node "curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs"
NODE_OK=$?
check_command npm "sudo apt install npm"
NPM_OK=$?

if [ $PHP_OK -ne 0 ] || [ $NODE_OK -ne 0 ] || [ $NPM_OK -ne 0 ]; then
    echo -e "${RED}Por favor, instala las dependencias necesarias y vuelve a ejecutar este script.${NC}"
    exit 1
fi

# Verificar instalación de libOQS-php
echo -e "${YELLOW}Verificando extensión oqsphp...${NC}"
php -r '
if (extension_loaded("oqsphp")) {
    echo "La extensión oqsphp está cargada correctamente\n";
    exit(0); // Disponible
} else {
    echo "La extensión oqsphp NO está cargada\n";
    exit(1); // No disponible
}
' 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ La extensión oqsphp está cargada correctamente${NC}"
else
    echo -e "${RED}❌ La extensión oqsphp no está cargada en PHP.${NC}"
    echo -e "${YELLOW}Para instalarla, sigue las instrucciones en liboqs-php/README.md:${NC}"
    echo -e "${YELLOW}1. Compila la extensión: cd liboqs-php && ./build.sh${NC}"
    echo -e "${YELLOW}2. Añade 'extension=/ruta/absoluta/a/liboqs-php/build/oqsphp.so' en tu php.ini${NC}"
    exit 1
fi

# Comprobar si las dependencias de npm están instaladas
if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
    echo -e "${YELLOW}Instalando dependencias de Node.js...${NC}"
    cd "$PROJECT_ROOT" && npm install
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error al instalar las dependencias de Node.js.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Dependencias de Node.js instaladas correctamente${NC}"
else
    echo -e "${GREEN}✓ Dependencias de Node.js ya instaladas${NC}"
fi

# Verificar que existe el archivo vite.config.js
if [ ! -f "$PROJECT_ROOT/vite.config.js" ]; then
    echo -e "${RED}Error: No se encontró el archivo vite.config.js${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Se usará la configuración existente de Vite${NC}"

# Actualizar el puerto del servidor en demo.html
echo -e "${YELLOW}Actualizando configuración en demo.html...${NC}"
sed -i "s/window.SERVER_PORT = '.*';/window.SERVER_PORT = '$API_PORT';/" "$PROJECT_ROOT/demo.html"
echo -e "${GREEN}✓ Puerto del servidor actualizado en demo.html${NC}"

# Iniciar backend en segundo plano
echo -e "${YELLOW}Iniciando servidor backend PHP en http://localhost:$API_PORT${NC}"
cd "$PROJECT_ROOT" && php -S 0.0.0.0:$API_PORT > "$LOG_FILE" 2>&1 &
PHP_PID=$!
echo -e "${GREEN}✓ Servidor PHP iniciado con PID $PHP_PID${NC}"

# Esperar un momento a que el servidor PHP se inicie
sleep 2

# Verificar que el servidor PHP está funcionando
if ! ps -p $PHP_PID > /dev/null; then
    echo -e "${RED}Error: El servidor PHP no se pudo iniciar. Revisa el archivo de log: $LOG_FILE${NC}"
    exit 1
fi

# Iniciar el frontend
echo -e "${YELLOW}Iniciando frontend Vite en http://localhost:$VITE_PORT${NC}"
echo -e "${BLUE}ℹ${NC} Para acceder, utiliza la dirección http://localhost:$VITE_PORT"
echo -e "${BLUE}ℹ${NC} Para acceder desde otros dispositivos, usa la IP de tu equipo en la red"
echo -e "${YELLOW}CTRL+C para detener ambos servidores${NC}"

# Iniciar frontend usando el archivo vite.config.js existente
cd "$PROJECT_ROOT" && VITE_SERVER_PORT=$API_PORT npx vite

# Al presionar Ctrl+C, se ejecutará esta parte
echo -e "${YELLOW}Deteniendo servidores...${NC}"
kill $PHP_PID
echo -e "${GREEN}Servidores detenidos.${NC}"