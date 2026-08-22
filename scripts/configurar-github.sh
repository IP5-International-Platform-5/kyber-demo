#!/usr/bin/env bash
#
# Aplica en GitHub los ajustes del repositorio que no se pueden versionar en
# ficheros: etiquetas, protección de la rama principal y política de merge.
#
# Es idempotente: se puede ejecutar varias veces sin efectos raros.
# Requiere la CLI `gh` autenticada con permisos de administración del repo.
#
#   ./scripts/configurar-github.sh            # pide confirmación
#   ./scripts/configurar-github.sh --si        # sin preguntar
#
# Ver CONTRIBUTING.md.

set -euo pipefail

CONFIRMAR_AUTOMATICAMENTE=false
[[ "${1:-}" == "--si" ]] && CONFIRMAR_AUTOMATICAMENTE=true

command -v gh >/dev/null || { echo "Falta la CLI de GitHub (gh)." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh no está autenticado. Ejecuta: gh auth login" >&2; exit 1; }

REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
RAMA=$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)

echo "Repositorio:     $REPO"
echo "Rama principal:  $RAMA"
echo
echo "Se va a configurar:"
echo "  - Etiquetas de tipo, área, estado y especiales."
echo "  - Squash como única forma de mezclar, con borrado automático de la rama."
echo "  - Protección de '$RAMA': PR obligatorio, CI obligatoria, sin push directo."
echo

if [[ "$CONFIRMAR_AUTOMATICAMENTE" == false ]]; then
    read -r -p "¿Continuar? [s/N] " respuesta
    [[ "$respuesta" =~ ^[sS]$ ]] || { echo "Cancelado."; exit 0; }
fi

# --------------------------------------------------------------------------
# 1. Etiquetas
# --------------------------------------------------------------------------
echo
echo "== Etiquetas =="

etiqueta() {
    local nombre="$1" color="$2" descripcion="$3"

    # --force actualiza la etiqueta si ya existe, en vez de fallar.
    if gh label create "$nombre" --color "$color" --description "$descripcion" --force >/dev/null 2>&1; then
        echo "  ok  $nombre"
    else
        echo "  !!  $nombre (no se pudo crear)"
    fi
}

# Tipo — azules
etiqueta 'tipo: funcionalidad'  '1d76db' 'Capacidad nueva'
etiqueta 'tipo: error'          'd73a4a' 'Algo no funciona como debería'
etiqueta 'tipo: tarea'          'c5def5' 'Mantenimiento, refactor, herramientas'
etiqueta 'tipo: documentación'  '0075ca' 'Solo documentación'

# Área — verdes
etiqueta 'área: kem'         '0e8a16' 'Encapsulado de claves (Kyber / ML-KEM)'
etiqueta 'área: cifrado'     '0e8a16' 'AES-256-GCM y cifrado simétrico'
etiqueta 'área: api'         '0e8a16' 'Endpoints de /app y /api_server'
etiqueta 'área: front'       '0e8a16' 'Interfaz de la demo, Vite, CSS'
etiqueta 'área: docker'      '0e8a16' 'Imágenes, compose y nginx'
etiqueta 'área: infra'       '0e8a16' 'CI, despliegue, herramientas'

# Estado — amarillos
etiqueta 'estado: bloqueado'        'fbca04' 'Esperando algo externo'
etiqueta 'estado: en revisión'      'fbca04' 'Pendiente de revisión'
etiqueta 'estado: necesita diseño'  'fbca04' 'Hay que decidir el enfoque antes de programar'

# Especiales
etiqueta 'protocolo'             '5319e7' 'Cambia el formato en el cable: requiere acuerdo de diseño'
etiqueta 'seguridad'             'b60205' 'Implicaciones criptográficas o de seguridad'
etiqueta 'buena primera tarea'   '7057ff' 'Buen punto de entrada al proyecto'

# --------------------------------------------------------------------------
# 2. Política de merge
# --------------------------------------------------------------------------
echo
echo "== Política de merge =="

if gh api -X PATCH "repos/$REPO" \
    -F allow_squash_merge=true \
    -F allow_merge_commit=false \
    -F allow_rebase_merge=false \
    -F delete_branch_on_merge=true \
    -F allow_auto_merge=true \
    -f squash_merge_commit_title='PR_TITLE' \
    -f squash_merge_commit_message='PR_BODY' \
    >/dev/null 2>&1; then
    echo "  ok  solo squash, título = título del PR, borrado automático de rama"
else
    echo "  !!  no se pudo aplicar (¿faltan permisos de administración?)"
fi

# --------------------------------------------------------------------------
# 3. Protección de la rama principal
# --------------------------------------------------------------------------
echo
echo "== Protección de '$RAMA' =="

# Los contextos son los nombres de los jobs de .github/workflows/ci.yml.
# Si renombras un job, actualízalos aquí o el PR se quedará esperando siempre.
PROTECCION=$(cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Sintaxis (PHP 8.1)",
      "Sintaxis (PHP 8.4)",
      "Estilo y análisis estático (PHP)",
      "Front-end",
      "Título del PR (Conventional Commits)"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
)

# Notas sobre las opciones elegidas:
#   enforce_admins=false ....... Francisco puede desbloquear una urgencia.
#   review_count=0 ............. con un solo desarrollador habitual, exigir una
#                                aprobación externa bloquearía el repositorio.
#                                Súbelo a 1 en cuanto César trabaje de forma
#                                continua.
#   linear_history=true ........ obliga a squash o rebase: nada de merge commits.
#   conversation_resolution .... no se mezcla con hilos de revisión abiertos.

if RESPUESTA=$(printf '%s' "$PROTECCION" | gh api -X PUT "repos/$REPO/branches/$RAMA/protection" --input - 2>&1); then
    echo "  ok  PR obligatorio, CI obligatoria, historial lineal, sin force push"
elif printf '%s' "$RESPUESTA" | grep -q 'Upgrade to GitHub Pro'; then
    # GitHub no permite proteger ramas en repositorios PRIVADOS con plan Free,
    # ni con protección clásica ni con rulesets. No es un fallo del script.
    ES_PRIVADO=$(gh repo view "$REPO" --json isPrivate --jq .isPrivate)
    echo "  !!  NO DISPONIBLE en este repositorio."
    echo
    echo "      '$REPO' es privado (isPrivate=$ES_PRIVADO) y la organización está"
    echo "      en plan Free. GitHub no ofrece protección de ramas ahí."
    echo
    echo "      Tres salidas, por orden de coste:"
    echo "        1. Instalar el hook local:  ./scripts/instalar-hooks.sh"
    echo "           Bloquea el push directo a '$RAMA' en tu máquina. Es lo que"
    echo "           hay hoy, pero solo protege a quien lo tenga instalado."
    echo "        2. Hacer el repositorio público: la protección pasa a estar"
    echo "           disponible gratis. Decisión de confidencialidad, no técnica."
    echo "        3. GitHub Team en la organización: protección en repos privados."
    echo
    echo "      Todo lo demás (etiquetas y política de merge) SÍ se ha aplicado."
else
    echo "  !!  no se pudo aplicar. Respuesta de GitHub:"
    printf '%s\n' "$RESPUESTA" | sed 's/^/      /'
    echo "      Alternativa: Settings → Branches → Add rule, a mano."
fi

# --------------------------------------------------------------------------
# 4. Limpieza de las etiquetas por defecto de GitHub
# --------------------------------------------------------------------------
echo
echo "== Etiquetas por defecto de GitHub =="

# GitHub crea estas al abrir el repositorio y duplican las nuestras
# ('bug' vs 'tipo: error', 'enhancement' vs 'tipo: funcionalidad'...).
# Tener dos juegos hace que se etiquete a medias y que los filtros no sirvan.
for sobrante in bug documentation duplicate enhancement 'good first issue' \
                'help wanted' invalid question wontfix; do
    if gh label delete "$sobrante" --repo "$REPO" --yes >/dev/null 2>&1; then
        echo "  borrada  $sobrante"
    fi
done

# --------------------------------------------------------------------------
# 5. Hooks locales
# --------------------------------------------------------------------------
echo
echo "== Hooks locales =="
echo "  Este script no los instala: son configuración de TU clon, no del"
echo "  repositorio remoto. Ejecuta cuando quieras:"
echo "      ./scripts/instalar-hooks.sh"

echo
echo "Listo. Revisa el resultado en: https://github.com/$REPO/settings"
