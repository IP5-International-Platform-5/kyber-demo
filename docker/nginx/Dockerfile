# syntax=docker/dockerfile:1
# Compila el frontend (Vite → dist/) y empaqueta Nginx con esa salida.

# Imágenes fijadas por digest, no por etiqueta: una etiqueta como "8.4-fpm-bookworm"
# cambia de contenido sin cambiar de nombre, y entonces la compilación deja de ser
# reproducible (QSLP/1 §19.8). Para actualizarlas, ver README, «Entorno de trabajo».
FROM node:24-bookworm@sha256:64af3819f9275802414d7cdc38c27e9d82bd564dec4d4da87d008255d36c63b4 AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html demo.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginx:alpine@sha256:1ed1b0e1d7652937d6cbdaf4018c7b6fc009a7dd6c3047351e2eddda745de43f
COPY --from=frontend /app/dist /var/www/html/dist
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
