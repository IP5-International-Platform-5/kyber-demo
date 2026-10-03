#!/bin/sh
set -e
mkdir -p /var/www/html/logs

# El directorio se monta desde el anfitrión y lo crea root, así que php-fpm
# —que trabaja como www-data— no podría escribir en él. Sin esto, el primer
# aviso de PHP sale antes de las cabeceras y rompe la respuesta de todos los
# endpoints.
chown -R www-data:www-data /var/www/html/logs 2>/dev/null || true
chmod 0775 /var/www/html/logs 2>/dev/null || true
exec docker-php-entrypoint "$@"
