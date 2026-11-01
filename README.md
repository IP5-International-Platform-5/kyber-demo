# Kyber Post-Quantum Cryptography PoC

Key exchange and message encryption using **ML-KEM-768** (FIPS 203, the standardised form of Kyber), exposed as a PHP API with an interactive web demo.

> **Proof of concept.** This repository illustrates a Kyber-based key exchange and message flow for learning and experimentation. It is **not** a hardened product: there is no authentication on the APIs, there are no signatures, and many operational concerns are out of scope. **Do not** deploy it as-is for real users or sensitive data. See [Security](#security).



## Table of contents

- [Entorno de trabajo](#entorno-de-trabajo)
- [Installation](#installation)
- [Architecture](#architecture)
- [API (endpoints)](#api-endpoints)
- [No repudio y evidencia](#no-repudio-y-evidencia)
- [Transparencia y auditoría](#transparencia-y-auditoría)
- [Communication flow](#communication-flow)
- [Demo](#demo)
- [Development](#development)
- [Security](#security)



## Entorno de trabajo

**El entorno de referencia es el contenedor, no tu máquina.** La demo solo se
ejecuta dentro de Docker, porque necesita la extensión `oqsphp`, que no se
instala con el gestor de paquetes de ninguna distribución.

| Componente | Versión fijada | Dónde se fija |
| ---------- | -------------- | ------------- |
| PHP (ejecución) | 8.4 | `docker/php/Dockerfile`, imagen fijada por digest |
| PHP (mínimo soportado) | 8.1 | `composer.json`: `require.php` y `config.platform.php` |
| liboqs | 0.16.0 | `docker/php/Dockerfile`, `ARG LIBOQS_TAG`. La imagen lo deja escrito: `docker compose exec php cat /etc/liboqs-version` |
| oqsphp (binding) | commit `8f929d2` | submódulo `liboqs-php` |
| Node | 24 | `.nvmrc`, `engines` de `package.json` e imágenes por digest |
| Nginx | `alpine` | `docker/nginx/Dockerfile`, imagen fijada por digest |
| Algoritmo KEM | ML-KEM-768 (FIPS 203) | constante `KEM_ALG` en `libs/kyber_utils.php` |

### Qué hace falta en local

| Herramienta | Para qué | Instalación en Arch/Manjaro |
| ----------- | -------- | --------------------------- |
| Docker + Compose | Ejecutar la demo. Es lo único imprescindible | `sudo pacman -S docker docker-compose` |
| PHP 8.x | `php -l` y las herramientas de estilo. **No ejecuta la demo** | `sudo pacman -S php` |
| Composer | Dependencias de desarrollo | `sudo pacman -S composer` |
| Node 24 | Solo si tocas el front fuera del contenedor | `nvm use` |

`docker compose` es un plugin del cliente de Docker: si `docker compose version`
responde «unknown command», falta el paquete `docker-compose`, aunque el demonio
esté funcionando.

La extensión `sodium` hará falta para la zeroización de material de clave. El
módulo viene con PHP pero llega desactivado: hay que descomentar
`extension=sodium` en `/etc/php/php.ini`.

### Por qué por digest y no por etiqueta

Una etiqueta como `php:8.4-fpm-bookworm` cambia de contenido sin cambiar de
nombre, y el guion de compilación de `liboqs-php` clonaba la rama `main` de
liboqs. Con las dos cosas juntas, dos compilaciones en fechas distintas podían
traer conjuntos de algoritmos distintos: en liboqs 0.15.0 desapareció Dilithium
y en 0.16.0, SPHINCS+. Para un proyecto que aspira a que sus registros tengan
valor probatorio, no poder decir con qué código se generó una firma es un
defecto, no una molestia.

La contrapartida es real: **fijar por digest congela también las actualizaciones
de seguridad de la imagen base**. Conviene revisarlas una vez al mes, y ante
cualquier aviso, en un commit propio que diga qué sube y por qué:

```bash
docker pull php:8.4-fpm-bookworm
docker inspect --format '{{index .RepoDigests 0}}' php:8.4-fpm-bookworm
docker manifest inspect php:8.4-fpm-bookworm@sha256:<el que vayas a fijar>
```

El tercer comando no es opcional: **un digest puede pudrirse**. Estas imágenes se
reconstruyen a menudo y el registro deja de servir los manifiestos que se quedan
sin etiqueta, así que un digest tomado de la API web puede caducar en horas.
Aquí pasó: se fijó uno que el registro ya no sirve y la compilación seguía
funcionando en local —la imagen estaba en el almacén—, pero en una máquina limpia
o en la CI el `FROM` habría fallado. Toma siempre el digest que verifica el
propio demonio, y confirma que `manifest inspect` responde en lugar de
`manifest verification failed` antes de confirmarlo en git.

### Lo que todavía no está fijado

- Los *runners* de la CI usan `ubuntu-latest`, que es una etiqueta móvil, y las
  acciones se fijan por versión mayor (`actions/checkout@v4`), no por commit.
- `composer.json` y `composer.lock` reales viven en la rama del protocolo, sin
  mezclar: en `main` el `composer.json` está vacío.
- `package-lock.json` no concuerda hoy con `package.json`, así que `npm ci`
  —y por tanto la imagen de Nginx— no compila hasta regenerarlo.

## Installation

Pick one setup guide:


| Method                           | Guide                              | When to use                                 |
| -------------------------------- | ---------------------------------- | ------------------------------------------- |
| **Docker (Windows/Linux/macOS)** | [SETUP-DOCKER.md](SETUP-DOCKER.md) | Fastest try-out; no local PHP/oqsphp build. |
| **Linux (Debian/Ubuntu)**        | [SETUP-LINUX.md](SETUP-LINUX.md)   | PHP + **oqsphp** on the host; dev with `php -S` and Vite, or Nginx + PHP-FPM. |


Both need the **liboqs-php** git submodule (`git clone --recursive` or `git submodule update --init --recursive`).

## Architecture

The **browser** is the front end. Two logical backends cooperate over HTTP:


| Path          | Role                                                                                                    |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `app/`        | User application backend — encapsulation (`get_shared_secret`) and AES-GCM encrypt (`encrypt_message`). |
| `api_server/` | Kyber server API — public key, decapsulation (`set_shared_secret`), decrypt (`decrypt_message`).        |
| `libs/`       | Shared PHP helpers (`kyber_utils.php`), identidad, recibos, Merkle, diario y evidencia.                  |
| `journal/`    | Diario encadenado, recibos y raíces de época. Hashes y firmas, nunca mensajes ni claves.                 |
| `log/`        | Log de transparencia: rol aparte, con identidad propia (`checkpoint`, `entries`, `proof`, `consistency`, `acts`, `gossip`). |
| `transparency/` | Hojas del log, sus checkpoints firmados y el índice de sujetos. Público por definición (§12.4).        |
| `auditor/`    | Lo que el auditor ha visto, **fuera** del log: si viviera dentro, un log que miente podría borrarlo.     |
| `dist/`       | Built static front (Vite).                                                                              |


Each backend has its own `config.php` and `cors_headers.php`. In a real deployment these would be different hosts; here they are two folders on one machine. **No key material is written to disk:** each side keeps its own copy of the shared secret in the ephemeral store (APCu), under a session identifier both ends derive separately. Sessions last five minutes. If steps get out of order, start again from “get public key”; there is nothing to delete.

The `demo.html` page groups calls that would normally go to `app` and `api_server` separately.

## API (endpoints)



### 1. Get public key

- **URL:** `/api_server/get_public_key`
- **Method:** POST
- **Body:**
  ```json
  {
    "client_nonce": "32_random_bytes_base64"
  }
  ```
- **Response:** `key_id`, `public_key`, `public_key_length`, `server_nonce`,
  `identity`, `identity_fingerprint` and `signature`.

  The key pair is **ephemeral**: generated for this request, the private half
  never leaves memory, destroyed after one decapsulation.

  The `signature` is ML-DSA-65 over a transcript covering both nonces, the
  `key_id`, the ephemeral key and the identity. **It is what stops a
  man-in-the-middle swapping the key for their own** (§7.2); without it the
  encryption protects you from whoever is listening, but not from whoever is
  in the middle. The client nonce is there so an old signed offer cannot be
  replayed at you.



### 2. Create shared secret

- **URL:** `/app/get_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "public_key": "server_public_key_base64",
    "key_id": "handle_from_step_1",
    "client_nonce": "the_one_sent_in_step_1",
    "server_nonce": "from_step_1",
    "identity": "server_identity_base64",
    "signature": "server_signature_base64"
  }
  ```
- **Response:** `sid`, `ciphertext`, `secret_fingerprint`, `confirmation`, this
  node's own `identity` and `signature`, and the fingerprints of both parties.
- **409** if the signature does not cover the offer, or if the server identity
  differs from the pinned one.

  The shared secret itself never leaves the backend. The `sid` is **derived**
  from the secret and the transcript, not invented: both ends reach the same
  value on their own, so a client cannot pick or fix one (QSLP/1 §7.4).



### 3. Send shared secret

- **URL:** `/api_server/set_shared_secret`
- **Method:** POST
- **Body:**
  ```json
  {
    "ciphertext": "kyber_ciphertext_base64",
    "key_id": "handle_from_step_1",
    "identity": "client_identity_base64",
    "signature": "client_signature_base64"
  }
  ```
- **Response:** `sid`, `secret_fingerprint` and `confirmation`, which must match
  the ones the app side reported, plus both fingerprints.
- **409** if the `key_id` is unknown, expired or already used; if the client
  signature does not cover the answer; or if the client identity changed.



### 4. Encrypt message

- **URL:** `/app/encrypt_message`
- **Method:** POST
- **Body:**
  ```json
  {
    "message": "plaintext_message",
    "sid": "session_identifier"
  }
  ```
- **Response:** `encrypted_data`, `iv` y `tag` (AES-256-GCM) en **base64**, más
  `seq`, `rc_hash` y el `receipt_core` que se ha firmado.

Lo que se cifra ya no es el mensaje suelto, sino un sobre con el mensaje, el
`receipt_core` y la firma del emisor. La firma va **dentro** del cifrado para no
publicar a quien mire el cable quién habla con quién (§11.1).

### 5. Decrypt message

- **URL:** `/api_server/decrypt_message`
- **Method:** POST
- **Body:**
  ```json
  {
    "encrypted_data": "base64_ciphertext",
    "iv": "base64_iv",
    "tag": "base64_auth_tag",
    "sid": "session_identifier"
  }
  ```
- **Response:** `message`, `seq`, `rc_hash`, `epoch` y el `receipt` firmado.
- **400 `E_AUTH`** si el `receipt_core` firmado no corresponde a esta sesión, si
  el contenido no resume al valor firmado o si la firma no verifica. El mensaje
  **no** se entrega en ninguno de esos casos.
- **400 `E_CLOCK_SKEW`** si la marca de tiempo se aparta más de 120 s (§6.2).
- **409 `E_REPLAY`** si el `seq` ya se había visto o queda fuera de la ventana
  de 64 posiciones (§8.2).
- **409** si la sesión es desconocida o ha caducado. No hay secreto guardado al
  que recurrir, que es justamente la idea.

### 6. Archivar el acuse de recibo

- **URL:** `/app/store_receipt`
- **Method:** POST
- **Body:** `sid`, `rc_hash` y el objeto `receipt` que devolvió el paso 5.
- **Response:** `receipt_verified`, `by` y `journal_n`.
- **400 `E_AUTH`** si la firma del acuse no verifica contra la identidad del par
  de esta sesión, o si dice venir de otro nodo.

El emisor comprueba la firma del acuse y lo anota en su propio diario. Hasta
que eso ocurre, lo que tiene es una cadena de texto; después, la prueba de que
el mensaje se entregó y se aceptó (§11.2).

### 7. Anclar las épocas

- **URL:** `/api_server/anchor_epoch`
- **Method:** POST
- **Body:** `{"force": true}` para cerrar además la época en curso.
- **Response:** `anchored`, `epochs` (con `root`, `size` y `anchor`) y
  `last_checkpoint`.

Un despliegue real hace esto con un temporizador de 60 s; aquí no hay
planificador, así que las épocas vencidas se cierran cuando alguien toca el
nodo, y este endpoint permite hacerlo a mano.

### 8. Exportar un paquete de evidencia

- **URL:** `/api_server/evidence`
- **Method:** POST
- **Body:** `rc_hash` y, opcionalmente, `payload` con el texto en claro.
- **Response:** el `evidence_package` de la §19.3, con sangrado para que lo
  pueda leer una persona.
- **404** si este nodo no conserva registro de ese recibo.



### 9-13. El log de transparencia

Son de un rol aparte, con su propia identidad, y sus respuestas son públicas
(§12.4): la seguridad no depende de que el registro sea secreto.

| Endpoint | Qué devuelve |
| --- | --- |
| `GET /log/checkpoint` | El último checkpoint firmado, con el contador total de entradas y la identidad pública del log. |
| `GET /log/entries?from=&count=&type=` | Las hojas del log. |
| `GET /log/proof?seq=` | Prueba de inclusión de una entrada, firmada por el log. |
| `GET /log/consistency?from_size=` | Prueba de que el árbol de ese tamaño es prefijo del actual (logarítmica, RFC 6962). |
| `GET /log/acts?node_id=` | Actos de autoridad contra un nodo, con prueba de inclusión o de **no** inclusión. |
| `POST /log/gossip` | Recibe un checkpoint visto en otro sitio y dice si encaja con la vista de ahora. |

## No repudio y evidencia

Un AEAD autentica al emisor **ante el receptor**, porque los dos tienen la misma
clave: no prueba nada ante un tercero, que no puede saber cuál de los dos
calculó el tag. Esta parte es la que convierte el canal en algo oponible
(§11, §19).

**Qué hace cada mensaje ahora:**

1. El emisor firma un `receipt_core` —`sid`, `seq`, `from`, `to`, `ts`,
   `payload_hash`, `th`— con su identidad ML-DSA-65, y la firma viaja dentro del
   cifrado. Nombrar a los dos extremos y al handshake no es decoración: impide
   que el receptor reenvíe la firma a un tercero como si hubiera sido para él.
2. El receptor comprueba la firma **antes** de entregar el contenido, y después
   devuelve un acuse firmado sobre `SHA3-256(receipt_core)`. Esa segunda mitad
   es la que protege al nodo débil: sin ella, el nodo central siempre puede
   sostener que no llegó nada.
3. El hash del recibo entra en el árbol de Merkle de su época. Al cerrarla se
   ancla **solo la raíz**: 32 bytes por época, sin mensajes ni identificadores
   personales. Cualquier nodo demuestra que su mensaje estaba incluido con
   log₂(n) hashes, sin ver los de los demás.
4. Los dos roles anotan lo suyo en un diario *append-only* encadenado por
   hashes y firman checkpoints. Quien reescriba su historia produce una cadena
   que contradice un checkpoint que él mismo firmó: la manipulación no se
   impide, se hace **detectable y demostrable**.

**Qué queda en disco.** En `journal/` hay el diario de cada rol
(`app.jsonl`, `srv.jsonl`), sus checkpoints, los registros de recibo y las
raíces de época. Solo hashes, identificadores y firmas: ni texto en claro ni
material de clave (§15.2, §19.2). El directorio se deja legible a propósito —un
diario que solo puede leer quien lo escribe no sirve para auditar a nadie.

**El verificador.** Una evidencia que solo sabe comprobar quien opera el
servidor no es evidencia, así que el paquete se verifica con un programa aparte
que no comparte una línea de código con los endpoints y no usa la red:

```bash
curl -s -X POST http://localhost:8080/api_server/evidence \
  -H 'Content-Type: application/json' \
  -d '{"rc_hash":"<hash>","payload":"<mensaje>"}' > evidencia.json

docker compose exec php php scripts/verificar-evidencia.php evidencia.json \
    --emisor=ip5:… --receptor=ip5:…
```

El informe enumera cada comprobación con cuatro resultados posibles, y la
diferencia importa: `[ SÍ ]` cuadra, `[ NO ]` falla —y entonces el paquete no
sostiene lo que afirma—, `[ !! ]` es una **carencia del paquete** y `[ -- ]` es
algo que el programa no puede decidir. Hoy salen tres carencias fijas: no hay
sello de tiempo cualificado, el anclaje es local y no hay estado de revocación.
Están escritas en el informe a propósito, porque son lo que un tercero echaría
en falta.

Sin `--emisor`, lo que el programa no comprueba es precisamente lo más fácil de
dar por supuesto: que esas claves públicas son de quien el paquete dice. Sin
cadena de certificados (§5.3) eso se ata desde fuera.

## Transparencia y auditoría

El paso 5 dejó la evidencia bien firmada, pero custodiada por el nodo central,
que es justo el adversario que la §3 llama **A4** y del que la especificación
dice que *es el que la arquitectura centralizada de IP5 introduce y el que su
documentación no contempla*. Esta parte es la que lo acota (§12, §19.5).

**El log es un rol aparte.** Tiene identidad ML-DSA propia y firma sus propios
checkpoints, así que el nodo central no puede fabricarlos. En este demostrador
corre en la misma máquina que todo lo demás: la separación es de claves y de
código, no física, y conviene decirlo en voz alta.

**Qué se publica.** Las identidades (mientras no haya CA, el log de
certificados de la §12.1 es un log de identidades), todo acto de autoridad
contra un nodo, la raíz de cada época de recibos y los huecos declarados en la
numeración de épocas.

**Lo que esto cambia en el handshake.** Una identidad que no venga con su
prueba de inclusión en el log se rechaza, en los dos sentidos. Así, para
suplantar a un nodo hay que dejarlo escrito en un registro público.

**Actos de autoridad.** Rechazar a un nodo es un acto con efectos sobre él, y
la §12.2 no admite actos invisibles: se registran con motivo, evidencia y
autor. La regla que la acompaña está implementada literalmente: *un bloqueo que
no aparece en el log es inválido*, así que si el acto no se puede registrar, el
rechazo **no se ejecuta** y se responde 503 diciendo por qué. No bloquear no es
aceptar: es que el acto no surte efecto.

**Prueba de que algo NO pasó.** Los actos se indexan en un árbol de Merkle
disperso por sujeto, lo que permite demostrar que **no existe** ningún acto
contra un `node_id`. Es la mitad que casi todos los sistemas omiten (§19.5), y
la que permite al nodo central acusado de censura probar que no censuró. Por lo
mismo, toda época se ancla aunque esté vacía: si las vacías no se anclaran, un
hueco en la numeración no se distinguiría de «no hubo mensajes».

### Detectar una vista dividida

Es la pieza más importante de la §12.3. Una autoridad puede mostrar vistas
distintas del log a distintos usuarios y ningún observador aislado lo notaría,
porque cada uno ve un log coherente. Lo que lo delata es comparar.

```bash
# El auditor guarda lo que ha visto en auditor/, fuera del log
docker compose exec php php scripts/auditar-log.php http://web

# Y el log compara contra un checkpoint que alguien vio en otro sitio
curl -s -X POST http://localhost:8080/log/gossip \
  -H 'Content-Type: application/json' \
  -d '{"checkpoint": <checkpoint firmado>}'
```

El auditor exige al log que demuestre que su vista de ahora **contiene** la de
antes. Si no puede, conserva el checkpoint anterior y lo dice: las dos firmas
juntas son la prueba, y la puede presentar cualquiera, porque las dos son del
propio log.

Un log honesto, además, **se niega a firmar** un checkpoint que contradiga el
que ya publicó: si alguien le reescribe una hoja por detrás, `/log/checkpoint`
devuelve 500 y dice que su contenido contradice su propia firma, en lugar de
seguir firmando como si nada. Para poder comprobar que la detección funciona
hace falta simular al log que sí miente, y de eso se encarga
`scripts/simular-vista-dividida.php`, que firma la otra vista con la misma
clave. No forma parte del protocolo: está ahí porque una defensa que no se ha
visto fallar no se ha comprobado.

Preguntarle al log si se ha contradicho solo funciona mientras conteste; por eso
la memoria del auditor vive en `auditor/` y no en el log. Lo que todavía no hay
es *gossip* de verdad entre varios nodos independientes: con un solo auditor,
la cobertura es la que es.

## Communication flow

1. Front requests the public key: `/api_server/get_public_key`. La oferta viaja
   con la prueba de que la identidad del servidor consta en el log (§12.1).
2. User app backend verifica esa prueba, publica su propia identidad y
   encapsula: `/app/get_shared_secret`.
3. Front sends the ciphertext: `/api_server/set_shared_secret`.
4. Server decapsulates with its private key and derives the same shared secret.
5. User app backend signs and encrypts: `/app/encrypt_message`.
6. Server verifies, decrypts and answers with a signed receipt:
   `/api_server/decrypt_message`.
7. The sender verifies and files that receipt: `/app/store_receipt`.
8. Every epoch, the server anchors the Merkle root of the receipts it processed:
   `/api_server/anchor_epoch`.
9. Either side can export a self-contained evidence package:
   `/api_server/evidence`.



## Demo

The `demo.html` page walks through the flow by calling the backends. The browser **does not** run Kyber in JavaScript: post-quantum work is done by **PHP** in `app/` and `api_server/`.

- Fetches the server public key.
- Agrees the shared secret via the API (Kyber on the server).
- Encrypts and decrypts with AES-GCM using that secret.

A browser-only front would need WebAssembly or another Kyber module; here encapsulation and encrypt live in `app/` as the user backend, separate from `api_server/` on a real network.

URLs depend on your setup — see [SETUP-DOCKER.md](SETUP-DOCKER.md) (port **8080** or **5173** with `dev`) or [SETUP-LINUX.md](SETUP-LINUX.md).

## Development

While editing, use **`npm run docker:dev`** or **`npm run dev` / `npm run full`** (Linux) — Vite serves `src/main.js` and HTML from disk; **F5** shows changes. Plain **`docker compose up`** on **8080** serves a built `dist/` and will **not** reflect `main.js` edits until you rebuild **web**.

| Command            | Description                                                            |
| ------------------ | ---------------------------------------------------------------------- |
| `npm run dev`      | Vite dev server on the host (proxies `/app` and `/api_server` to PHP). |
| `npm run full`     | Host: `php -S` + Vite (see [SETUP-LINUX.md](SETUP-LINUX.md)).          |
| `npm run build`    | Writes static assets to `dist/`.                                       |
| `npm run preview`  | Serves `dist/` with API proxy (`vite.config.js`).                      |
| `npm run docker:*` | Docker workflows — see [SETUP-DOCKER.md](SETUP-DOCKER.md).             |


`npm run build` produces `dist/` for any static host or Nginx next to `app/`, `api_server/`, and `libs/`.

Copy `.env.example` to `.env` if you need custom ports or proxy targets. **Do not commit** `.env`.

A gitignored `custom/` directory is available for your own deploy scripts.

## Security

This repository is a **proof of concept**: educational and demonstrative, **not** audited or intended for production use. Before any real deployment you would need at least:

Done so far, following QSLP/1:

- **Mutually authenticated exchange.** Both sides hold a long-lived ML-DSA-65
  identity and sign the handshake transcript, so neither the ephemeral key nor
  the answer can be substituted in transit (§7.2, §7.3).
- **No ephemeral key material at rest.** Key pairs are ephemeral, the shared
  secret lives only in the ephemeral store, and nothing is written to disk
  (§15.4). The signing identities *are* on disk, with `0600`, because an
  identity is long-lived by definition (§5.2) — that is the opposite case, not
  an exception.
- **No secrets in logs or responses** (§15.2, §15.3). Responses carry a
  fingerprint; the log redacts by whitelist, so a field added later cannot leak
  by omission.
- **Session identifiers are derived, not accepted** from the client (§7.4).
- **Firma por mensaje y acuse firmado** (§11.1, §11.2). El emisor firma el
  `receipt_core` dentro del cifrado y el receptor responde con un acuse
  firmado, así que hay no repudio de origen **y** de recepción.
- **Anti-replay** con ventana deslizante de 64 posiciones y rechazo del desvío
  de reloj mayor de ±120 s (§8.2, §6.2).
- **Anclaje Merkle por época y diario encadenado con checkpoints firmados**
  (§11.4, §19.2), con paquete de evidencia exportable y un verificador
  independiente que funciona sin red (§19.3, §19.4).
- **Log de transparencia con identidad propia** (§12): identidades, actos de
  autoridad y raíces de época publicadas, con pruebas de inclusión firmadas y
  pruebas de consistencia logarítmicas del RFC 6962. El handshake rechaza una
  identidad que no conste publicada (§12.1).
- **Detección de vista dividida** (§12.3): un auditor guarda fuera del log lo
  que ha visto y exige que la vista de ahora contenga la de antes. Dos
  checkpoints firmados que no encajan son una prueba que cualquiera puede
  presentar.
- **Actos de autoridad registrados, y la regla dura que los acompaña** (§12.2):
  un rechazo que no se puede registrar no se ejecuta.
- **Pruebas de no ocurrencia** (§19.5): árbol de Merkle disperso por sujeto
  para demostrar que **no** existe ningún acto contra un nodo, épocas continuas
  y sin huecos —también las vacías— y contadores firmados en cada checkpoint.

Still missing, and it is a long list:

1. **Certificates and revocation.** Identities are raw keys pinned on first
   use, so the *first* exchange is unauthenticated and a changed identity can
   only be refused, never explained. A real deployment needs a CA, a
   transparency log and revocation (§5.3, §5.4, §12).
2. **The hybrid suite.** This is ML-KEM and ML-DSA alone; QSLP/1 requires them
   paired with their classical equivalents, so that a break in either one is
   survivable (§4.1).
3. **Sello de tiempo cualificado.** El cliente RFC 3161 está implementado, pero
   sale desactivado: sin `QSLP_TSA_URL` no hay TSA, y el paquete declara el
   sello ausente en lugar de inventarse una fecha. Hasta que haya una TSA
   cualificada, la hora la afirma el propio nodo y no es oponible (§11.3).
4. **Anclaje en cadena.** La raíz de cada época se ancla en el diario local
   detrás de una interfaz, porque no existe la cadena IP5. Es un compromiso
   firmado, pero lo custodia el mismo nodo al que auditas, que es precisamente
   lo que la §11.4 quiere evitar.
5. **El log no está separado de verdad.** Tiene identidad propia y el nodo
   central no puede firmar en su nombre, pero corre en la misma máquina y lo
   administra quien administra todo lo demás. Un log que se puede apagar a la
   vez que el nodo auditado no es un tercero.
6. **Gossip entre varios nodos.** La §12.3 quiere que los nodos ligeros
   intercambien checkpoints entre sí y con al menos un auditor. Aquí hay un
   auditor y un endpoint de comparación; con un solo observador, la cobertura
   es la que es.
7. **Los diarios locales siguen con consistencia lineal.** El log usa pruebas
   logarítmicas, pero la de la §19.2 entrega la tirada de entradas entre dos
   checkpoints.
8. **Autorización.** `anchor_epoch`, `evidence` y los endpoints del log
   responden a quien pregunte: las capacidades de la §13 no están
   implementadas. El log es público a propósito; los otros dos no deberían.
9. **Exportador en el nodo ligero.** El paquete de evidencia lo construye el
   nodo central; el ligero tiene su diario y su copia de las firmas, pero
   todavía no exporta por su cuenta.
10. **Una segunda implementación del verificador**, en otro lenguaje. Dos
    programas independientes que coinciden es un argumento mucho más fuerte
    ante un perito contrario que uno solo (§19.4).
11. **HTTPS** everywhere, and CORS that is not `*`.
12. Rate limiting.


## Contributing

Development workflow, branching model and pull request rules:
[CONTRIBUTING.md](CONTRIBUTING.md). Code style and file formatting:
[docs/guia-de-estilo.md](docs/guia-de-estilo.md). Security policy:
[SECURITY.md](SECURITY.md).

Both documents are written in Spanish, which is the working language of the
project. Quick start:

```bash
composer install && npm install
composer verificar    # syntax, style and static analysis
npm run formato       # front-end formatting

docker compose up -d --build
./scripts/prueba-e2e.sh    # end-to-end check against the running stack
```

`scripts/prueba-e2e.sh` walks the whole flow and then checks what must **fail**:
reusing an ephemeral key pair, inventing a session identifier, omitting it,
replaying a message, tampering with a receipt, rewriting the journal, and
finding key material on disk or in the log. A happy path that passes says
nothing about whether the defences are in place.

`composer pruebas` (`scripts/prueba-unidades.php`) comprueba sin HTTP las
piezas de las que depende todo lo demás: canonicalización, árbol de Merkle,
pruebas de consistencia del RFC 6962 par por par, árbol disperso y pruebas de
no inclusión, separación de dominios de firma, ventana anti-replay,
encadenamiento del diario, vista dividida y continuidad de las épocas. Son 141
comprobaciones dentro del contenedor y 98 en la prueba de extremo a extremo. Fuera del contenedor no hay extensión `oqsphp` y las comprobaciones de
firma se marcan como omitidas; dentro se ejecutan todas:

```bash
docker compose exec php php scripts/prueba-unidades.php
```

The protocol itself is defined by the reference implementation,
[ip5-kyber-poc](https://github.com/IP5-International-Platform-5/ip5-kyber-poc);
this repository follows it.
