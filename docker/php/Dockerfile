# syntax=docker/dockerfile:1
# Compila la extensión oqsphp (libOQS + SWIG) y la instala sobre php-fpm oficial.

# Imágenes fijadas por digest, no por etiqueta: una etiqueta como "8.4-fpm-bookworm"
# cambia de contenido sin cambiar de nombre, y entonces la compilación deja de ser
# reproducible (QSLP/1 §19.8). Para actualizarlas, ver README, «Entorno de trabajo».
FROM php:8.4-fpm-bookworm@sha256:fb06b33cf42d420c9bff770f6d0556cc26d896e6854fdb8ca32f63f8a0c126e8 AS extension-builder

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
# build.sh clona la rama main de liboqs, así que dos compilaciones en fechas
# distintas pueden traer conjuntos de algoritmos distintos: en 0.15.0 desapareció
# Dilithium y en 0.16.0 SPHINCS+. Fijar la etiqueta es un requisito forense
# (QSLP/1 §19.8), no higiene. build.sh respeta LIBOQS_ROOT y no vuelve a clonar.
ARG LIBOQS_TAG=0.16.0
ENV LIBOQS_ROOT=/build/liboqs
RUN git clone --depth 1 --branch "${LIBOQS_TAG}" \
        https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_ROOT}"

# Con `sh` el guion falla en silencio: usa sintaxis de bash (`[[`, ${…/…}), así
# que bajo dash la comprobación de LIBOQS_ROOT no se evalúa y clona main
# igualmente, dejando el fijado de versión sin efecto. Se ejecuta con bash.
RUN chmod +x build.sh && bash ./build.sh

# La imagen deja constancia de con qué liboqs se construyó: sin eso no se puede
# decir con qué código se generó una firma (§19.8).
RUN cd "${LIBOQS_ROOT}" && (git describe --tags --always 2>/dev/null || echo desconocida) > /build/liboqs-version.txt

FROM php:8.4-fpm-bookworm@sha256:fb06b33cf42d420c9bff770f6d0556cc26d896e6854fdb8ca32f63f8a0c126e8

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=extension-builder /build/liboqs-php/build/oqsphp.so /tmp/oqsphp.so
COPY --from=extension-builder /build/liboqs-version.txt /etc/liboqs-version
RUN EXT_DIR="$(php -r 'echo ini_get("extension_dir");')" \
    && mv /tmp/oqsphp.so "${EXT_DIR}/" \
    && echo "extension=oqsphp" > /usr/local/etc/php/conf.d/docker-php-ext-oqsphp.ini

# APCu da memoria compartida entre los procesos de php-fpm. Hace falta para que
# el material de clave viva en memoria y no en ficheros: las sesiones de PHP
# escriben en disco, que es justo lo que §15.4 y el paso 3 de §18 quieren evitar.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ${PHPIZE_DEPS} \
    && pecl install apcu \
    && docker-php-ext-enable apcu \
    && apt-get purge -y --auto-remove ${PHPIZE_DEPS} \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

COPY docker/php/docker-entrypoint.sh /usr/local/bin/kyber-docker-entrypoint.sh
RUN chmod +x /usr/local/bin/kyber-docker-entrypoint.sh

ENTRYPOINT ["kyber-docker-entrypoint.sh"]
CMD ["php-fpm"]
