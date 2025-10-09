#!/bin/bash
# Script para verificar que el entorno es Linux

# Detectar sistema operativo
OS_TYPE=$(uname -s)

if [[ "$OS_TYPE" != "Linux" && "$OS_TYPE" != "Darwin" ]]; then
    echo -e "\033[0;31mError: Este script debe ejecutarse en Linux o macOS, no en Windows\033[0m"
    echo -e "\033[0;31mSistema operativo detectado: $OS_TYPE\033[0m"
    echo -e "\033[0;33mSugerencia: Usa Windows Subsystem for Linux (WSL) o una máquina virtual con Linux para ejecutar este script.\033[0m"
    return 1 2>/dev/null || true
else
    echo -e "\033[0;32mSistema operativo compatible detectado: $OS_TYPE\033[0m"
    return 0 2>/dev/null || true
fi