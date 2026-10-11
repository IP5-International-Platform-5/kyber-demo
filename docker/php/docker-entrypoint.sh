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

# El diario encadenado, los recibos y las raíces de época (§11.4, §19.2). A
# diferencia de las identidades, esto se deja legible a propósito: un diario
# que solo puede leer quien lo escribe no sirve para auditar a nadie. Lo que no
# contiene, por norma, es texto en claro ni material de clave (§15.2).
mkdir -p /var/www/html/journal/receipts /var/www/html/journal/epochs
chown -R www-data:www-data /var/www/html/journal 2>/dev/null || true
chmod -R 0755 /var/www/html/journal 2>/dev/null || true
exec docker-php-entrypoint "$@"
