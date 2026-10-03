#!/usr/bin/env bash
#
# Instala los hooks de git versionados en .githooks/
#
# Los hooks NO se clonan con el repositorio: hay que activarlos en cada clon.
# Este script apunta core.hooksPath a .githooks/, así que a partir de ahí los
# hooks se actualizan solos con cada `git pull`.
#
#   ./scripts/instalar-hooks.sh
#
# Para desactivarlos:  git config --unset core.hooksPath

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ ! -d .githooks ]]; then
    echo "No existe el directorio .githooks/ en la raíz del repositorio." >&2
    exit 1
fi

chmod +x .githooks/*
git config core.hooksPath .githooks

echo "Hooks instalados (core.hooksPath = .githooks):"
for hook in .githooks/*; do
    [[ -f "$hook" ]] && echo "  - $(basename "$hook")"
done
echo
echo "El hook pre-push impide el push directo a la rama principal."
echo "Para desactivarlos:  git config --unset core.hooksPath"
