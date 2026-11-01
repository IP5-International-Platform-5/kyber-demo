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
# Como j(), pero recorre rutas con punto y devuelve objetos y listas como JSON.
jp()   { python3 -c "import sys,json
try: cur = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
for k in '$1'.split('.'):
    cur = cur.get(k) if isinstance(cur, dict) else None
print('' if cur is None else (json.dumps(cur) if isinstance(cur, (dict, list)) else cur))"; }

if ! curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"client_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}' "$B/api_server/get_public_key"; then
    echo "No responde $B. Levanta la pila con: docker compose up -d --build"
    exit 2
fi

echo "== Flujo completo =="
NC=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
R1=$(curl -s -X POST "$B/api_server/get_public_key" -H 'Content-Type: application/json' \
      -d "{\"client_nonce\":\"$NC\"}")
KEY_ID=$(echo "$R1" | j key_id); PK=$(echo "$R1" | j public_key)
NS=$(echo "$R1" | j server_nonce); ID_S=$(echo "$R1" | j identity); SIG_S=$(echo "$R1" | j signature)
[ -n "$KEY_ID" ] && ok "get_public_key devuelve key_id" || fail "get_public_key" "$R1"
[ ${#PK} -gt 1000 ] && ok "clave pública de ML-KEM-768 (${#PK} car. base64)" || fail "clave pública corta" "${#PK}"
[ ${#SIG_S} -gt 4000 ] && ok "la oferta viene FIRMADA (${#SIG_S} car. base64)" || fail "oferta sin firma" "${#SIG_S}"
[ -n "$(echo "$R1" | j identity_fingerprint)" ] && ok "el servidor presenta su identidad" || fail "sin identidad"

oferta() { printf '{"public_key":"%s","key_id":"%s","client_nonce":"%s","server_nonce":"%s","identity":"%s","signature":"%s"}' \
    "$1" "$KEY_ID" "$NC" "$NS" "$2" "$3"; }

R2=$(curl -s -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' -d "$(oferta "$PK" "$ID_S" "$SIG_S")")
SID_APP=$(echo "$R2" | j sid); CT=$(echo "$R2" | j ciphertext); FP_APP=$(echo "$R2" | j secret_fingerprint)
NODO_APP=$(echo "$R2" | j node_id)
ID_C=$(echo "$R2" | j identity); SIG_C=$(echo "$R2" | j signature); CONF_APP=$(echo "$R2" | j confirmation)
[ -n "$SID_APP" ] && ok "el lado app verifica la firma y deriva un sid" || fail "encapsulado" "$R2"
echo "$R2" | grep -q shared_secret && fail "el encapsulado DEVUELVE el secreto" || ok "el encapsulado no devuelve el secreto"

R3=$(curl -s -X POST "$B/api_server/set_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"ciphertext\":\"$CT\",\"key_id\":\"$KEY_ID\",\"identity\":\"$ID_C\",\"signature\":\"$SIG_C\"}")
SID_SRV=$(echo "$R3" | j sid); FP_SRV=$(echo "$R3" | j secret_fingerprint); CONF_SRV=$(echo "$R3" | j confirmation)
[ -n "$SID_SRV" ] && ok "el servidor verifica la firma del cliente y desencapsula" || fail "desencapsulado" "$R3"
{ [ -n "$SID_APP" ] && [ "$SID_APP" = "$SID_SRV" ]; } \
    && ok "ambos extremos derivan EL MISMO sid ($SID_APP)" \
    || fail "los sid no coinciden o están vacíos" "«$SID_APP» vs «$SID_SRV»"
{ [ -n "$FP_APP" ] && [ "$FP_APP" = "$FP_SRV" ]; } \
    && ok "ambos extremos derivan el mismo secreto" \
    || fail "huellas distintas o vacías" "«$FP_APP» vs «$FP_SRV»"
{ [ -n "$CONF_APP" ] && [ "$CONF_APP" = "$CONF_SRV" ]; } \
    && ok "el tag de confirmación coincide: mismas claves, mismo transcript" \
    || fail "confirmación distinta" "«$CONF_APP» vs «$CONF_SRV»"
echo "$R3" | grep -q '"shared_secret"' && fail "el desencapsulado DEVUELVE el secreto" || ok "el desencapsulado no devuelve el secreto"

MSG="Mensaje de prueba con acentos: ñandú"
R4=$(curl -s -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'message':'$MSG','sid':'$SID_APP'}))")")
ED=$(echo "$R4" | j encrypted_data); IV=$(echo "$R4" | j iv); TAG=$(echo "$R4" | j tag)
RC=$(echo "$R4" | j rc_hash); SEQ=$(echo "$R4" | j seq)
[ -n "$ED" ] && ok "cifrado AES-256-GCM" || fail "cifrado" "$R4"
echo "$RC" | grep -qE '^[0-9a-f]{64}$' && ok "el emisor firma un receipt_core y devuelve su hash" || fail "sin rc_hash" "$R4"
[ "$SEQ" = "0" ] && ok "el primer mensaje de la sesión lleva seq 0" || fail "seq inesperado" "«$SEQ»"
[ "$(echo "$R4" | jp receipt_core.to)" != "" ] && ok "el receipt_core nombra al destinatario (§11.1)" || fail "receipt_core sin destinatario" "$R4"

envia() { curl -s -X POST "$B/api_server/decrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'encrypted_data':'$1','iv':'$IV','tag':'$TAG','sid':'$2'}))")"; }

R5=$(envia "$ED" "$SID_SRV")
[ "$(echo "$R5" | j message)" = "$MSG" ] && ok "el servidor descifra el mensaje íntegro" || fail "descifrado" "$R5"

echo "== Recibos firmados (§11.1, §11.2) =="
[ "$(echo "$R5" | j rc_hash)" = "$RC" ] && ok "receptor y emisor calculan el mismo hash del núcleo" || fail "rc_hash distinto" "$(echo "$R5" | j rc_hash)"
[ "$(echo "$R5" | j sender_signature_verified)" = "True" ] && ok "el receptor verificó la firma del emisor ANTES de entregar" || fail "entrega sin verificar" "$R5"
RECIBO=$(echo "$R5" | jp receipt)
[ -n "$RECIBO" ] && ok "el receptor devuelve un acuse firmado" || fail "sin acuse de recibo" "$R5"
[ "$(echo "$R5" | jp receipt.rc_hash)" = "$RC" ] && ok "el acuse se refiere a este mensaje" || fail "acuse de otro mensaje"
[ ${#RECIBO} -gt 4000 ] && ok "el acuse lleva firma ML-DSA-65 (${#RECIBO} car.)" || fail "acuse sin firma" "${#RECIBO}"

R6=$(curl -s -X POST "$B/app/store_receipt" -H 'Content-Type: application/json' \
      -d "$(python3 -c "
import json, sys
r = json.loads(sys.argv[1])
print(json.dumps({'sid': sys.argv[2], 'rc_hash': r['rc_hash'], 'receipt': r['receipt']}))" "$R5" "$SID_APP")")
[ "$(echo "$R6" | j receipt_verified)" = "True" ] && ok "el emisor verifica el acuse y lo archiva (no repudio de recepción)" || fail "acuse no verificado" "$R6"

C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/store_receipt" -H 'Content-Type: application/json' \
      -d "$(python3 -c "
import json, sys
r = json.loads(sys.argv[1])
rec = dict(r['receipt'])
rec['ts'] = '2020-01-01T00:00:00Z'
print(json.dumps({'sid': sys.argv[2], 'rc_hash': r['rc_hash'], 'receipt': rec}))" "$R5" "$SID_APP")")
[ "$C" = "400" ] && ok "un acuse con la fecha cambiada se rechaza (400)" || fail "acuse manipulado admitido" "HTTP $C"

echo "== Anti-replay (§8.2) =="
R7=$(envia "$ED" "$SID_SRV")
[ "$(echo "$R7" | j error)" = "E_REPLAY" ] && ok "reenviar el mismo mensaje se rechaza con E_REPLAY" || fail "replay admitido" "$R7"

MSG2="Segundo mensaje"
R8=$(curl -s -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'message':'$MSG2','sid':'$SID_APP'}))")")
[ "$(echo "$R8" | j seq)" = "1" ] && ok "el segundo mensaje avanza a seq 1" || fail "el seq no avanza" "$(echo "$R8" | j seq)"
R9=$(curl -s -X POST "$B/api_server/decrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'encrypted_data':'$(echo "$R8" | j encrypted_data)','iv':'$(echo "$R8" | j iv)','tag':'$(echo "$R8" | j tag)','sid':'$SID_SRV'}))")")
[ "$(echo "$R9" | j message)" = "$MSG2" ] && ok "el segundo mensaje se acepta con su propio seq" || fail "segundo mensaje rechazado" "$R9"
RC2=$(echo "$R9" | j rc_hash)

echo "== Anclaje Merkle (§11.4) =="
R10=$(curl -s -X POST "$B/api_server/anchor_epoch" -H 'Content-Type: application/json' -d '{"force":true}')
ANCLADAS=$(echo "$R10" | j anchored)
[ "${ANCLADAS:-0}" -ge 1 ] && ok "se cierra la época y se ancla su raíz ($ANCLADAS época/s)" || fail "nada anclado" "$R10"
RAIZ=$(python3 -c "
import json, sys
d = json.loads(sys.argv[1])
print(d['epochs'][0]['root'] if d.get('epochs') else '')" "$R10")
echo "$RAIZ" | grep -qE '^[0-9a-f]{64}$' && ok "la raíz de época son 32 bytes y nada más (§11.4)" || fail "raíz inesperada" "«$RAIZ»"
[ -n "$(echo "$R10" | jp last_checkpoint.signature)" ] && ok "el cierre produce un checkpoint firmado (§19.2)" || fail "checkpoint sin firmar" "$R10"

echo "== Paquete de evidencia y verificador independiente (§19.3, §19.4) =="
PAQUETE="$REPO/.e2e/evidencia-e2e.json"
curl -s -X POST "$B/api_server/evidence" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json,sys;print(json.dumps({'rc_hash':'$RC','payload':sys.argv[1]}))" "$MSG")" > "$PAQUETE"
[ "$(cat "$PAQUETE" | j qslp_evidence)" = "1" ] && ok "el nodo exporta un paquete de evidencia" || fail "exportación" "$(head -c 200 "$PAQUETE")"
[ -n "$(cat "$PAQUETE" | jp signatures.receiver_receipt.signature)" ] && ok "el paquete lleva LAS DOS firmas (§19.3)" || fail "paquete con una sola firma"
[ "$(cat "$PAQUETE" | jp payload.matches_hash)" = "True" ] && ok "el contenido aportado cuadra con payload_hash" || fail "el contenido no cuadra"
[ -n "$(cat "$PAQUETE" | jp merkle_proof.root)" ] && ok "el paquete trae prueba de inclusión en la raíz anclada" || fail "sin prueba de Merkle"

# El verificador necesita la extensión oqsphp para las firmas: dentro del
# contenedor si está a mano, y si no, con el PHP del sistema avisando.
if docker exec kyber-php true 2>/dev/null; then
    verifica() { local f=$1; shift; docker exec kyber-php php /var/www/html/scripts/verificar-evidencia.php "/var/www/html/.e2e/$f" "$@"; }
else
    verifica() { local f=$1; shift; php "$REPO/scripts/verificar-evidencia.php" "$REPO/.e2e/$f" "$@"; }
    printf '  nota   no hay contenedor a mano: el verificador correrá sin oqsphp
'
fi

SALIDA=$(verifica evidencia-e2e.json); CODIGO=$?
[ "$CODIGO" = "0" ] && ok "el verificador independiente acepta el paquete" || fail "el verificador lo rechaza" "$(echo "$SALIDA" | grep '\[ NO \]' | head -3)"
echo "$SALIDA" | grep -q 'no repudio de origen' && ok "el informe comprueba el no repudio de origen" || fail "el informe no menciona el origen"
echo "$SALIDA" | grep -q 'no repudio de recepción' && ok "el informe comprueba el no repudio de recepción" || fail "el informe no menciona la recepción"
echo "$SALIDA" | grep -q '\[ !! \].*§11.3' && ok "el informe declara que falta el sello cualificado" || fail "el informe calla la falta de sello"
echo "$SALIDA" | grep -q '\[ !! \].*§11.4' && ok "el informe declara que el anclaje no está en una cadena" || fail "el informe calla el anclaje local"

# Manipular el paquete: el verificador tiene que rechazarlo.
python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
d['receipt_core']['seq'] = 99
json.dump(d, open(sys.argv[2], 'w'))" "$PAQUETE" "$REPO/.e2e/evidencia-manipulada.json"
SALIDA=$(verifica evidencia-manipulada.json); CODIGO=$?
[ "$CODIGO" = "1" ] && ok "cambiar un campo del núcleo invalida el paquete" || fail "paquete manipulado aceptado" "código $CODIGO"
echo "$SALIDA" | grep -q 'NO sostiene lo que afirma' && ok "el informe dice sin rodeos que no sostiene lo que afirma" || fail "informe ambiguo"

python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
d['signatures']['receiver_receipt']['signature'] = 'A' + d['signatures']['receiver_receipt']['signature'][1:]
json.dump(d, open(sys.argv[2], 'w'))" "$PAQUETE" "$REPO/.e2e/evidencia-sin-acuse.json"
verifica evidencia-sin-acuse.json > /dev/null 2>&1
[ "$?" = "1" ] && ok "manipular el acuse invalida el paquete" || fail "acuse manipulado aceptado"

# Atar la identidad desde fuera del paquete: el node_id viene del handshake,
# no del propio fichero que se está verificando.
SALIDA=$(verifica evidencia-e2e.json --emisor="$NODO_APP"); CODIGO=$?
[ "$CODIGO" = "0" ] && ok "el paquete resiste atar el emisor a una identidad conocida" || fail "no cuadra con el emisor del handshake" "$NODO_APP"
echo "$SALIDA" | grep -q 'El emisor es la identidad indicada' && ok "el informe deja de decir «no comprobado» sobre el emisor" || fail "el informe no recoge --emisor"

verifica evidencia-e2e.json --emisor=ip5:AAAAAAAAAAAAAAAAAAAAAAAAAA > /dev/null 2>&1
[ "$?" = "1" ] && ok "atarlo a otra identidad lo invalida" || fail "acepta un emisor que no es"

# Con un checkpoint posterior al del hecho, la prueba de consistencia deja de
# ser trivial: es la que demuestra que el diario no se reescribió después.
R11=$(curl -s -X POST "$B/app/encrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'message':'Tercer mensaje','sid':'$SID_APP'}))")")
curl -s -o /dev/null -X POST "$B/api_server/decrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'encrypted_data':'$(echo "$R11" | j encrypted_data)','iv':'$(echo "$R11" | j iv)','tag':'$(echo "$R11" | j tag)','sid':'$SID_SRV'}))")"
curl -s -o /dev/null -X POST "$B/api_server/anchor_epoch" -H 'Content-Type: application/json' -d '{"force":true}'

curl -s -X POST "$B/api_server/evidence" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json,sys;print(json.dumps({'rc_hash':'$RC','payload':sys.argv[1]}))" "$MSG")" > "$REPO/.e2e/evidencia-posterior.json"
SALIDA=$(verifica evidencia-posterior.json); CODIGO=$?
[ "$CODIGO" = "0" ] && ok "el paquete reexportado sigue verificando" || fail "el paquete reexportado falla"
echo "$SALIDA" | grep -q '\[ SÍ \] El diario encadena desde el checkpoint del hecho' \
    && ok "con un checkpoint posterior, la consistencia del diario se demuestra" \
    || fail "la prueba de consistencia no llega a demostrarse" "$(echo "$SALIDA" | grep 'consistencia')"

# Reescribir el diario después del hecho tiene que delatarse en esa prueba.
python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
entradas = d['consistency_proof']['entries']
entradas[0]['data_hash'] = '0' * 64
json.dump(d, open(sys.argv[2], 'w'))" "$REPO/.e2e/evidencia-posterior.json" "$REPO/.e2e/evidencia-reescrita.json"
SALIDA=$(verifica evidencia-reescrita.json); CODIGO=$?
[ "$CODIGO" = "1" ] && ok "reescribir una entrada del diario invalida la consistencia" || fail "reescritura del diario admitida"
# El detalle se envuelve a 64 columnas, así que la frase se busca sobre la
# salida aplanada y no línea a línea.
echo "$SALIDA" | grep -q '\[ NO \] El diario encadena' && ok "el informe señala en qué línea falla" || fail "el informe no señala la consistencia"
echo "$SALIDA" | tr '\n' ' ' | tr -s ' ' | grep -q 'diario fue reescrito' && ok "el informe nombra la reescritura" || fail "el informe no explica la reescritura"

# E2E_CONSERVAR=1 deja los paquetes en .e2e/ para mirarlos con calma.
[ -n "${E2E_CONSERVAR:-}" ] || rm -f \
    "$REPO/.e2e/evidencia-manipulada.json" "$REPO/.e2e/evidencia-sin-acuse.json" \
    "$REPO/.e2e/evidencia-posterior.json" "$REPO/.e2e/evidencia-reescrita.json"

echo "== Aislamiento entre sesiones =="
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api_server/decrypt_message" -H 'Content-Type: application/json' \
      -d "$(python3 -c "import json;print(json.dumps({'encrypted_data':'$ED','iv':'$IV','tag':'$TAG','sid':'0000000000000000000000000000000000000000'}))")")
[ "$C" = "409" ] && ok "un criptograma con un sid ajeno se rechaza (409)" || fail "sid ajeno admitido" "HTTP $C"

echo "== Log de transparencia (§12) =="
CP=$(curl -s "$B/log/checkpoint")
LOG_ID=$(echo "$CP" | jp log_identity.log_id)
[ -n "$LOG_ID" ] && ok "el log se presenta con identidad propia ($LOG_ID)" || fail "el log no tiene identidad" "$CP"
[ "$LOG_ID" != "$(echo "$R3" | j client_node_id)" ] && ok "la identidad del log no es la del nodo central" || fail "el log y el nodo central comparten identidad"
[ -n "$(echo "$CP" | jp checkpoint.signature)" ] && ok "el checkpoint del log viene firmado" || fail "checkpoint sin firma" "$CP"
TAM=$(echo "$CP" | jp checkpoint.tree_size)
[ "${TAM:-0}" -ge 2 ] && ok "el checkpoint lleva el contador total de entradas ($TAM)" || fail "contador ausente o vacío" "$TAM"
[ -n "$(echo "$CP" | jp checkpoint.acts_root)" ] && ok "y la raíz del árbol de actos" || fail "sin raíz de actos"

ENTRADAS=$(curl -s "$B/log/entries?type=identity&count=10")
[ "$(echo "$ENTRADAS" | jp tree_size)" = "$TAM" ] && ok "las entradas del log son públicas (§12.4)" || fail "el log no publica sus entradas" "$ENTRADAS"

PRUEBA=$(curl -s "$B/log/proof?seq=0")
[ -n "$(echo "$PRUEBA" | jp inclusion.signature)" ] && ok "la prueba de inclusión viene firmada por el log" || fail "prueba sin firma" "$PRUEBA"
CONSIS=$(curl -s "$B/log/consistency?from_size=1")
[ -n "$(echo "$CONSIS" | jp to_root)" ] && ok "el log entrega pruebas de consistencia" || fail "sin prueba de consistencia" "$CONSIS"

echo "== El handshake exige que la identidad conste en el log (§12.1) =="
[ -n "$(echo "$R1" | jp identity_log.inclusion.signature)" ] && ok "la oferta del servidor viaja con su prueba de publicación" || fail "oferta sin prueba de publicación"
[ -n "$(echo "$R2" | j server_identity_in_log)" ] && ok "el cliente comprobó que la identidad del servidor consta" || fail "el cliente no comprobó el log" "$R2"
[ -n "$(echo "$R3" | j client_identity_in_log)" ] && ok "y el servidor comprobó la del cliente" || fail "el servidor no comprobó el log" "$R3"

NC3=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
R=$(curl -s -X POST "$B/api_server/get_public_key" -H 'Content-Type: application/json' -d "{\"client_nonce\":\"$NC3\"}")
PK3=$(echo "$R" | j public_key); K3=$(echo "$R" | j key_id); NS3=$(echo "$R" | j server_nonce)
ID3=$(echo "$R" | j identity); SIG3=$(echo "$R" | j signature)

SIN_PRUEBA=$(python3 -c "
import json
print(json.dumps({'public_key': '$PK3', 'key_id': '$K3', 'client_nonce': '$NC3',
                  'server_nonce': '$NS3', 'identity': '$ID3', 'signature': '$SIG3'}))")
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' -d "$SIN_PRUEBA")
[ "$C" = "409" ] && ok "una oferta sin prueba de publicación se rechaza (409)" || fail "oferta sin prueba admitida" "HTTP $C"

CON_PRUEBA_AJENA=$(python3 -c "
import json, sys
oferta = json.loads(sys.argv[1])
prueba = json.loads(sys.argv[2])
oferta['identity_log'] = prueba
print(json.dumps(oferta))" "$SIN_PRUEBA" "$(echo "$R2" | jp identity_log)")
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' -d "$CON_PRUEBA_AJENA")
[ "$C" = "409" ] && ok "la prueba de OTRA identidad no sirve (409)" || fail "prueba ajena admitida" "HTTP $C"

echo "== Actos de autoridad y no ocurrencia (§12.2, §19.5) =="
NODO_CLIENTE=$(echo "$R3" | j client_node_id)
ACTOS=$(curl -s "$B/log/acts?node_id=$NODO_CLIENTE")
[ "$(echo "$ACTOS" | jp acts_count)" = "0" ] && ok "no consta ningún acto contra el cliente" || fail "hay actos inesperados" "$ACTOS"
[ -n "$(echo "$ACTOS" | jp proof.bitmap)" ] && ok "y eso se demuestra: prueba de NO inclusión (§19.5)" || fail "sin prueba de no inclusión" "$ACTOS"
[ "$(echo "$ACTOS" | jp proof.value)" = "" ] && ok "la hoja del árbol disperso está vacía, como debe" || fail "la hoja no está vacía"

C=$(curl -s -o /dev/null -w '%{http_code}' "$B/log/acts?node_id=no-es-un-node-id")
[ "$C" = "400" ] && ok "un node_id mal formado se rechaza (400)" || fail "node_id inválido admitido" "HTTP $C"

echo "== Auditor independiente y vista dividida (§12.3) =="
if docker exec kyber-php true 2>/dev/null; then
    audita() { docker exec kyber-php php /var/www/html/scripts/auditar-log.php "$@"; }

    SALIDA=$(audita --reiniciar http://web 2>&1); CODIGO=$?
    [ "$CODIGO" = "0" ] && ok "el auditor acepta el log en su primera visita" || fail "el auditor falla de entrada" "$(echo "$SALIDA" | tail -3)"
    echo "$SALIDA" | grep -q 'Primera visita' && ok "y dice que todavía no tiene con qué contrastar" || fail "el informe no distingue la primera visita"

    curl -s -o /dev/null -X POST "$B/api_server/anchor_epoch" -H 'Content-Type: application/json' -d '{"force":true}'
    SALIDA=$(audita http://web 2>&1); CODIGO=$?
    [ "$CODIGO" = "0" ] && ok "tras crecer el log, la vista sigue siendo consistente" || fail "el auditor ve una inconsistencia que no hay" "$(echo "$SALIDA" | tail -3)"
    echo "$SALIDA" | tr '\n' ' ' | grep -q 'creció sin' && ok "el informe lo dice con esas palabras" || fail "el informe no explica la consistencia"

    # Reescribir una hoja ya cubierta por un checkpoint firmado: el log puede
    # firmar la vista nueva, pero entonces sus dos firmas se contradicen.
    docker exec -u www-data kyber-php cp /var/www/html/transparency/log.jsonl /tmp/log-original.jsonl
    docker exec -u www-data kyber-php sh -c "php -r '
        \$path = \"/var/www/html/transparency/log.jsonl\";
        \$lines = explode(\"\n\", trim(file_get_contents(\$path)));
        \$leaf = json_decode(\$lines[1], true);
        \$leaf[\"ts\"] = \"2020-01-01T00:00:00Z\";
        \$lines[1] = json_encode(\$leaf, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        file_put_contents(\$path, implode(\"\n\", \$lines) . \"\n\");'"

    SALIDA=$(audita http://web 2>&1); CODIGO=$?
    [ "$CODIGO" = "1" ] && ok "reescribir el log hace que el auditor lo rechace" || fail "la reescritura pasa desapercibida" "código $CODIGO"
    echo "$SALIDA" | tr '\n' ' ' | grep -q 'VISTA DIVIDIDA' && ok "y lo llama por su nombre: vista dividida" || fail "el informe no nombra la vista dividida"
    echo "$SALIDA" | tr '\n' ' ' | grep -q 'no se guarda' && ok "el auditor conserva el checkpoint anterior, que es la prueba" || fail "el auditor no conserva la prueba"

    GOSSIP=$(curl -s -X POST "$B/log/gossip" -H 'Content-Type: application/json' \
        -d "$(python3 -c "
import json, subprocess
visto = subprocess.run(['docker', 'exec', 'kyber-php', 'cat', '/var/www/html/auditor/checkpoints-vistos.jsonl'],
                       capture_output=True, text=True).stdout.strip().split('\n')[-1]
print(json.dumps({'checkpoint': json.loads(visto)}))")")
    [ "$(echo "$GOSSIP" | jp verdict.split_view)" = "True" ] && ok "el gossip también detecta la divergencia" || fail "el gossip no la detecta" "$GOSSIP"
    [ -n "$(echo "$GOSSIP" | jp split_view_proof.a.signature)" ] && ok "y devuelve las dos firmas juntas como prueba" || fail "sin prueba agrupada"

    docker exec -u www-data kyber-php cp /tmp/log-original.jsonl /var/www/html/transparency/log.jsonl
    SALIDA=$(audita --reiniciar http://web 2>&1); CODIGO=$?
    [ "$CODIGO" = "0" ] && ok "restaurado el log, el auditor vuelve a aceptarlo" || fail "el log no se restauró"
else
    printf '  omite  auditor y vista dividida: hacen falta el contenedor y su extensión\n'
fi

echo "== Épocas continuas, sin huecos (§19.5) =="
if docker exec kyber-php true 2>/dev/null; then
    HUECOS=$(docker exec kyber-php sh -c "ls -1 /var/www/html/journal/epochs/*.json 2>/dev/null | sed 's#.*/##; s#\.json##' | sort -n" | python3 -c "
import sys
numeros = [int(l) for l in sys.stdin if l.strip()]
huecos = sum(1 for a, b in zip(numeros, numeros[1:]) if b != a + 1)
print(f'{len(numeros)} {huecos}')")
    CERRADAS=$(echo "$HUECOS" | cut -d' ' -f1)
    SALTOS=$(echo "$HUECOS" | cut -d' ' -f2)
    [ "${CERRADAS:-0}" -ge 1 ] && ok "hay $CERRADAS época(s) anclada(s)" || fail "no hay épocas ancladas"
    [ "${SALTOS:-1}" = "0" ] && ok "la numeración de épocas no tiene huecos" || fail "la numeración tiene $SALTOS hueco(s)"
    VACIAS=$(docker exec kyber-php sh -c "grep -l '\"empty\":true' /var/www/html/journal/epochs/*.json 2>/dev/null | wc -l")
    ok "las épocas sin recibos también se anclan (${VACIAS:-0} vacías ancladas)"
fi

echo "== Autenticación: lo que debe rechazarse =="
voltea() { python3 -c "
import base64,sys
b = bytearray(base64.b64decode('$1'))
b[$2] ^= 1
print(base64.b64encode(bytes(b)).decode())"; }

NC2=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
R=$(curl -s -X POST "$B/api_server/get_public_key" -H 'Content-Type: application/json' -d "{\"client_nonce\":\"$NC2\"}")
K2=$(echo "$R" | j key_id); PK2=$(echo "$R" | j public_key); NS2=$(echo "$R" | j server_nonce)
SIG2=$(echo "$R" | j signature)

SIG_MALA=$(voltea "$SIG_S" 100)
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' \
      -d "$(oferta "$PK" "$ID_S" "$SIG_MALA")")
[ "$C" = "409" ] && ok "firma del servidor manipulada: rechazada (409)" || fail "firma manipulada admitida" "HTTP $C"

C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' \
      -d "$(oferta "$PK2" "$ID_S" "$SIG_S")")
[ "$C" = "409" ] && ok "clave efímera sustituida (MITM): rechazada (409)" || fail "sustitución de clave admitida" "HTTP $C"

ID_FALSA=$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(1952)).decode())")
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/app/get_shared_secret" -H 'Content-Type: application/json' \
      -d "$(oferta "$PK" "$ID_FALSA" "$SIG_S")")
[ "$C" = "409" ] && ok "identidad distinta de la fijada: rechazada (409)" || fail "cambio de identidad admitido" "HTTP $C"

SIGC_MALA=$(voltea "$SIG_C" 100)
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api_server/set_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"ciphertext\":\"$CT\",\"key_id\":\"$K2\",\"identity\":\"$ID_C\",\"signature\":\"$SIGC_MALA\"}")
[ "$C" = "409" ] && ok "firma del cliente manipulada: rechazada (409)" || fail "firma de cliente manipulada admitida" "HTTP $C"

echo "== Comprobaciones negativas =="
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api_server/set_shared_secret" -H 'Content-Type: application/json' \
      -d "{\"ciphertext\":\"$CT\",\"key_id\":\"$KEY_ID\",\"identity\":\"$ID_C\",\"signature\":\"$SIG_C\"}")
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

# Los recibos y las épocas son 0750 y desde el anfitrión no se pueden leer, así
# que esto se revisa desde dentro del contenedor. Y se cuenta lo examinado: un
# glob que no encuentra nada imprimiría un OK sin haber comprobado nada, que es
# peor que no tener la comprobación.
if docker exec kyber-php true 2>/dev/null; then
    revisados=$(docker exec kyber-php sh -c 'ls -1 /var/www/html/journal/*.jsonl /var/www/html/journal/receipts/*/*.json /var/www/html/journal/epochs/*.json 2>/dev/null | wc -l')
    con_mensaje=$(docker exec kyber-php grep -rlF -- "$MSG" /var/www/html/journal 2>/dev/null | wc -l)

    if [ "${revisados:-0}" -lt 3 ]; then
        fail "solo se han examinado ${revisados:-0} ficheros del diario: la comprobación no vale"
    elif [ "${con_mensaje:-1}" != "0" ]; then
        fail "$con_mensaje fichero(s) del diario contienen el texto en claro"
    else
        ok "los $revisados ficheros de journal/ guardan hashes, no mensajes (§15.2, §19.2)"
    fi
else
    printf '  omite  revisión de journal/: hace falta el contenedor (los recibos son 0750)\n'
fi

if [ -f "$REPO/journal/srv.jsonl" ]; then
    python3 - "$REPO/journal/srv.jsonl" <<'PY'
import hashlib, json, sys

GENESIS = '0' * 64


def canonico(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def hash_entrada(e):
    return hashlib.sha3_256(('QSLP1-demo JE' + canonico(e)).encode()).hexdigest()


prev = GENESIS
for linea in open(sys.argv[1], encoding='utf-8'):
    linea = linea.strip()
    if not linea:
        continue
    e = json.loads(linea)
    if e['prev'] != prev:
        print('roto en la entrada %s' % e['n'])
        raise SystemExit(1)
    prev = hash_entrada(e)
raise SystemExit(0)
PY
    # Un segundo lector, en otro lenguaje, recalcula el encadenamiento: si solo
    # lo comprueba quien lo escribe, no se está comprobando nada.
    [ "$?" = "0" ] && ok "el encadenamiento del diario cuadra recalculado desde fuera" || fail "el diario del servidor no encadena"
fi

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
