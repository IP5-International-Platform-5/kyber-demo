# syntax=docker/dockerfile:1
# Compila la extensión oqsphp (libOQS + SWIG) y la instala sobre php-fpm oficial.

FROM php:8.4-fpm-bookworm AS extension-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    cmake \
    ninja-build \
    build-essential \
    swig \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/liboqs-php
COPY liboqs-php/ .
RUN chmod +x build.sh && ./build.sh

FROM php:8.4-fpm-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=extension-builder /build/liboqs-php/build/oqsphp.so /tmp/oqsphp.so
RUN EXT_DIR="$(php -r 'echo ini_get("extension_dir");')" \
    && mv /tmp/oqsphp.so "${EXT_DIR}/" \
    && echo "extension=oqsphp" > /usr/local/etc/php/conf.d/docker-php-ext-oqsphp.ini

WORKDIR /var/www/html

COPY docker/php/docker-entrypoint.sh /usr/local/bin/kyber-docker-entrypoint.sh
RUN chmod +x /usr/local/bin/kyber-docker-entrypoint.sh

ENTRYPOINT ["kyber-docker-entrypoint.sh"]
CMD ["php-fpm"]
