#!/usr/bin/env bash
#
# Prueba de extremo a extremo contra la pila levantada.
#
#   docker compose up -d --build
#   ./scripts/prueba-e2e.sh [http://localhost:8080]
#
# Comprueba el flujo completo y, sobre todo, lo que debe fallar: reutilizar un
# par de claves efímero, inventarse un identificador de sesión y omitirlo. Un
# flujo feliz que pasa no dice nada sobre si las defensas están puestas.

set -u
B=${1:-http://localhost:8080}
REPO="$(cd "$(dirname "$0")/.." && pwd)"
fallos=0

ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf ' FALLO  %s  %s\n' "$1" "${2:-}"; fallos=$((fallos + 1)); }
j()    { python3 -c "import sys,json
try: d = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
print(d.get('$1',''))"; }

if ! curl -sf -o /dev/null "$B/api_server/get_public_key"; then
    echo "No responde $B. Levanta la pila con: docker compose up -d --build"
    exit 2
fi

echo "== Flujo completo =="
R1=$(curl -s "$B/api_server/get_public_key")
KEY_ID=$(echo "$R1" | j key_id); PK=$(echo "$R1" | j public_key)
[ -n "$KEY_ID" ] && ok "get_public_key devuelve key_id" || fail "get_public_key" "$R1"
[ ${#PK} -gt 1000 ] && ok "clave pública de ML-KEM-768 (${#PK} car. base64)" || fail "clave pública corta" "${#PK}"

R2=$(curl -s -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"public_key\":\"$PK\",\"key_id\":\"$KEY_ID\"}")
SID_APP=$(echo "$R2" | j sid); NONCE=$(echo "$R2" | j nonce)
CT=$(echo "$R2" | j ciphertext); FP_APP=$(echo "$R2" | j secret_fingerprint)
[ -n "$SID_APP" ] && ok "el lado app deriva un sid" || fail "encapsulado" "$R2"
echo "$R2" | grep -q shared_secret && fail "el encapsulado DEVUELVE el secreto" || ok "el encapsulado no devuelve el secreto"

R3=$(curl -s -X POST "$B/api_server/set_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"ciphertext\":\"$CT\",\"nonce\":\"$NONCE\",\"key_id\":\"$KEY_ID\"}")
SID_SRV=$(echo "$R3" | j sid); FP_SRV=$(echo "$R3" | j secret_fingerprint)
[ -n "$SID_SRV" ] && ok "el servidor deriva un sid" || fail "desencapsulado" "$R3"
{ [ -n "$SID_APP" ] && [ "$SID_APP" = "$SID_SRV" ]; } \
    && ok "ambos extremos derivan EL MISMO sid ($SID_APP)" \
    || fail "los sid no coinciden o están vacíos" "«$SID_APP» vs «$SID_SRV»"
{ [ -n "$FP_APP" ] && [ "$FP_APP" = "$FP_SRV" ]; } \
    && ok "ambos extremos derivan el mismo secreto" \
    || fail "huellas distintas o vacías" "«$FP_APP» vs «$FP_SRV»"
echo "$R3" | grep -q shared_secret && fail "el desencapsulado DEVUELVE el secreto" || ok "el desencapsulado no devuelve el secreto"

MSG="Mensaje de prueba con acentos: ñandú"
R4=$(curl -s -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'message':'$MSG','sid':'$SID_APP'}))")")
ED=$(echo "$R4" | j encrypted_data); IV=$(echo "$R4" | j iv); TAG=$(echo "$R4" | j tag)
[ -n "$ED" ] && ok "cifrado AES-256-GCM" || fail "cifrado" "$R4"

R5=$(curl -s -X POST "$B/api_server/decrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'encrypted_data':'$ED','iv':'$IV','tag':'$TAG','sid':'$SID_SRV'}))")")
[ "$(echo "$R5" | j message)" = "$MSG" ] && ok "el servidor descifra el mensaje íntegro" || fail "descifrado" "$R5"

echo "== Comprobaciones negativas =="
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api_server/set_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"ciphertext\":\"$CT\",\"nonce\":\"$NONCE\",\"key_id\":\"$KEY_ID\"}")
[ "$C" = "409" ] && ok "reutilizar el key_id se rechaza (409): la clave privada murió al usarse" || fail "reutilización de key_id admitida" "HTTP $C"

C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' \
      -d '{"message":"x","sid":"0000000000000000000000000000000000000000"}')
[ "$C" = "409" ] && ok "un sid inventado se rechaza (409)" || fail "sid inventado admitido" "HTTP $C"

C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' -d '{"message":"x"}')
[ "$C" = "400" ] && ok "sin sid se rechaza (400)" || fail "falta de sid admitida" "HTTP $C"

echo "== Nada de material de clave en disco =="
for d in api_server/keys app/keys; do
    n=$(find "$REPO/$d" -type f 2>/dev/null | wc -l)
    [ "$n" = "0" ] && ok "$d sin ficheros" || fail "$d contiene $n fichero(s)"
done

L="$REPO/logs/requests.log"
if [ -f "$L" ]; then
    grep -q '"shared_secret"' "$L" && fail "el registro contiene shared_secret" || ok "el registro no contiene shared_secret"
    grep -qE '"(sid|secret_fingerprint)":"[0-9a-f ]{10,}"' "$L" \
        && fail "el registro expone sid o huella en claro" \
        || ok "sid y huella salen redactados del registro"
fi

echo
[ "$fallos" = "0" ] && echo "Todo correcto." || echo "$fallos comprobación(es) fallida(s)."
exit "$fallos"
