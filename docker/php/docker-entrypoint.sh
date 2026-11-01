#!/bin/sh
set -e
mkdir -p /var/www/html/logs

# El directorio se monta desde el anfitrión y lo crea root, así que php-fpm
# —que trabaja como www-data— no podría escribir en él. Sin esto, el primer
# aviso de PHP sale antes de las cabeceras y rompe la respuesta de todos los
# endpoints.
chown -R www-data:www-data /var/www/html/logs 2>/dev/null || true
chmod 0775 /var/www/html/logs 2>/dev/null || true

# Las identidades de firma sí viven en disco, a diferencia del material efímero:
# son de larga vida por definición (§5.2). El directorio es solo para www-data.
mkdir -p /var/www/html/identities
chown -R www-data:www-data /var/www/html/identities 2>/dev/null || true
chmod 0700 /var/www/html/identities 2>/dev/null || true

# El diario encadenado, los recibos y las raíces de época (§11.4, §19.2). Nada
# de esto contiene texto en claro ni material de clave (§15.2), pero no todo
# tiene el mismo público:
#
#   journal/*.jsonl      el diario y los checkpoints firmados. Legibles: son lo
#                        que se publica, y un diario que solo puede leer quien
#                        lo escribe no sirve para auditar a nadie (§12, §19.2).
#   journal/receipts/    los registros de recibo llevan from, to y ts, o sea
#                        quién habló con quién y cuándo. Eso es metadato de
#                        comunicaciones: se queda en 0750, mínima exposición.
#   journal/epochs/      igual, por coherencia; lo que sale al exterior de una
#                        época es su raíz, dentro del paquete de evidencia.
mkdir -p /var/www/html/journal
chown www-data:www-data /var/www/html/journal 2>/dev/null || true
chmod 0755 /var/www/html/journal 2>/dev/null || true

mkdir -p /var/www/html/journal/receipts /var/www/html/journal/epochs
chown -R www-data:www-data /var/www/html/journal/receipts /var/www/html/journal/epochs 2>/dev/null || true
chmod 0750 /var/www/html/journal/receipts /var/www/html/journal/epochs 2>/dev/null || true
# Log de transparencia (§12) y memoria del auditor. El log es público por
# definición —la seguridad no depende de que el registro sea secreto— así que
# queda legible; el auditor guarda aparte lo que ha visto, porque si su memoria
# viviera dentro del log, un log que miente podría borrarla.
mkdir -p /var/www/html/transparency /var/www/html/auditor
chown -R www-data:www-data /var/www/html/transparency /var/www/html/auditor 2>/dev/null || true
chmod 0755 /var/www/html/transparency /var/www/html/auditor 2>/dev/null || true

exec docker-php-entrypoint "$@"
