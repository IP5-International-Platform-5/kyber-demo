# Política de seguridad

Este repositorio es una **prueba de concepto criptográfica**. No está auditado
y no debe usarse tal cual en producción.

## Cómo reportar una vulnerabilidad

**No abras un issue público.** Los issues de este repositorio son visibles para
toda la organización y un fallo criptográfico descrito en público es explotable
antes de estar corregido.

Usa una de estas dos vías:

1. Un aviso privado de seguridad en GitHub:
   *Security → Advisories → Report a vulnerability*.
2. Correo directo a Francisco: `francisco.costacano@unir.net`.

Incluye qué falla, cómo reproducirlo y qué garantía se rompe. Respuesta en un
plazo razonable; al ser un proyecto pequeño no hay SLA formal.

## Qué cuenta como vulnerabilidad aquí

- Fuga de material de clave: clave privada, secreto compartido o `session_id`
  en logs, en mensajes de error, en la respuesta HTTP o en disco sin cifrar.
- Reutilización de IV con la misma clave en AES-GCM.
- Que el par de claves asimétrico **no** se destruya tras la decapsulación
  (rompe la *forward secrecy*, que es la propiedad central de la PoC).
- Aceptar un mensaje cuyo tag GCM no verifica.
- Sesiones que no expiran, o cuya expiración se puede eludir desde el cliente.
- Cualquier vía para descifrar sin conocer el secreto compartido.

## Limitaciones conocidas y asumidas

No hace falta reportarlas: están documentadas y son deliberadas en esta fase.

- El secreto compartido se usa directamente como clave AES-256 sin pasar por un
  KDF. Para producción hay que derivarla con HKDF.
- El `session_id` y los metadatos no se autentican como *associated data* de GCM.
- Las sesiones de PHP guardan material de clave en disco. En producción hay que
  usar un almacén en memoria con expiración real.
- El transporte de la PoC es HTTP plano en local; en despliegue va detrás de TLS.
- La demo enseña a propósito material criptográfico en pantalla (claves,
  ciphertext, secreto compartido): ese es su cometido didáctico. No la
  despliegues con datos reales.

## Reglas para quien contribuye

- Nunca subir claves, `.env`, el contenido de `keys/`, `app/keys/`,
  `api_server/keys/` ni volcados de sesión. El `.gitignore` los cubre, pero la
  responsabilidad es de quien hace el commit.
- Nunca escribir secretos ni claves en `error_log`, `var_dump` o `echo`, ni
  siquiera de forma temporal para depurar.
- Comparar material criptográfico siempre con `hash_equals()`, nunca con `===`
  sobre datos que dependan de una entrada del atacante.
- Toda aleatoriedad viene de `random_bytes()`; jamás de `rand()`, `mt_rand()`
  ni `uniqid()`.
- Si un commit ha filtrado un secreto: rotarlo **primero**, reescribir el
  historial después. Un secreto que ha estado en un repositorio remoto se
  considera comprometido aunque se borre el commit.
