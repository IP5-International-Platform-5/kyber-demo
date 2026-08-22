<!--
  El TÍTULO del PR se convierte en el mensaje del commit de main (usamos
  squash merge), así que debe seguir Conventional Commits:

      <tipo>(ámbito opcional): descripción en minúscula y en imperativo

  Ejemplos:  feat(demo): muestra las longitudes de clave en cada paso
             fix(demo): no reutilizar el IV al renegociar
  La CI rechaza el PR si el título no cumple el formato.
-->

## Qué hace

<!-- Dos o tres frases. Qué cambia desde fuera, no cómo está implementado. -->

## Por qué

Closes #<!-- número del issue. Si no hay issue, explica aquí el motivo. -->

## Cómo se ha probado

<!-- Comandos concretos y su resultado. "Funciona" no es una prueba. -->

```
composer verificar
npm run build
npm run docker:up   # y recorrer la demo en el navegador
```

## Impacto en el protocolo

- [ ] **No cambia nada en el cable**: mismo JSON, mismos endpoints, mismo handshake.
- [ ] **Cambia el protocolo**: se aparta de `ip5-kyber-poc`, que es la
      implementación de referencia. Descrito abajo y acordado previamente.

<!-- Si cambia el protocolo, describe aquí el antes y el después del formato. -->

## Comprobaciones

- [ ] `composer verificar` pasa en local (sintaxis, estilo y PHPStan).
- [ ] `npm run build` compila y la demo funciona en el navegador.
- [ ] La rama está al día con `main` (`git pull --rebase origin main`).
- [ ] No se ha subido ningún secreto: claves, `keys/`, `.env`, volcados de
      sesión ni ciphertext real.
- [ ] No se ha modificado el submódulo `liboqs-php` sin querer
      (`git status` no debe mencionarlo).
- [ ] Ningún secreto, clave ni material criptográfico se escribe en logs ni en
      mensajes de error.
- [ ] La documentación (README / `docs/`) refleja el cambio, si aplica.
- [ ] El PR es lo más pequeño posible: un solo asunto.
