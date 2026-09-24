# syntax=docker/dockerfile:1
# Compila el frontend (Vite → dist/) y empaqueta Nginx con esa salida.

# Imágenes fijadas por digest, no por etiqueta: una etiqueta como "8.4-fpm-bookworm"
# cambia de contenido sin cambiar de nombre, y entonces la compilación deja de ser
# reproducible (QSLP/1 §19.8). Para actualizarlas, ver README, «Entorno de trabajo».
FROM node:20-bookworm@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5 AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html demo.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginx:alpine@sha256:1ed1b0e1d7652937d6cbdaf4018c7b6fc009a7dd6c3047351e2eddda745de43f
COPY --from=frontend /app/dist /var/www/html/dist
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
