# syntax=docker/dockerfile:1
# Compila el frontend (Vite → dist/) y empaqueta Nginx con esa salida.

FROM node:20-bookworm AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html demo.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginx:alpine
COPY --from=frontend /app/dist /var/www/html/dist
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
