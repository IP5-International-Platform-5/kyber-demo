#!/bin/sh
set -e
mkdir -p /var/www/html/logs
exec docker-php-entrypoint "$@"
