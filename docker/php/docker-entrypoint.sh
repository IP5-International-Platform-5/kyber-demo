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
exec docker-php-entrypoint "$@"
