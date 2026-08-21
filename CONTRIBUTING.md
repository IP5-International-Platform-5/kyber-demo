# Protocolo de trabajo

Cómo se desarrolla en este repositorio. Es corto a propósito: el equipo es de
una o dos personas y el proceso tiene que costar menos que el trabajo.

La guía de formato y nomenclatura del código está aparte, en
[`docs/guia-de-estilo.md`](docs/guia-de-estilo.md).

> **Este repositorio no define el protocolo.** La implementación de referencia
> es [`ip5-kyber-poc`](https://github.com/IP5-International-Platform-5/ip5-kyber-poc):
> el formato de trama, el handshake y la política de rekey se deciden allí, y
> esta demo se adapta a ellos. Nunca al revés.

> **Rama principal:** `main` en los dos repositorios. `ip5-kyber-poc` se llamaba
> `master` hasta el 21 de agosto de 2026: si tienes un clon anterior de aquel,
> renómbrala en local con `git branch -m master main && git fetch origin --prune`.

---

## 1. Puesta en marcha

```bash
git clone --recurse-submodules git@github.com:IP5-International-Platform-5/kyber-demo.git
cd kyber-demo
composer install
npm install
./scripts/instalar-hooks.sh # hooks de git, una vez por clon
composer verificar          # sintaxis, estilo y PHPStan
npm run build               # compila el front
```

El `--recurse-submodules` importa: `liboqs-php` es un submódulo. Si ya clonaste
sin él:

```bash
git submodule update --init --recursive
```

Comandos disponibles:

| Comando                   | Qué hace                                              |
| ------------------------- | ----------------------------------------------------- |
| `composer sintaxis`       | `php -l` sobre todo el código PHP.                      |
| `composer estilo`         | Comprueba el formato PHP sin modificar ficheros.        |
| `composer estilo:aplicar` | Aplica el formato PHP. **Este es el que usas al escribir.** |
| `composer analisis`       | PHPStan nivel 5.                                        |
| `composer verificar`      | Los tres primeros, en orden.                            |
| `npm run formato`         | Comprueba el formato de JS, CSS y HTML.                 |
| `npm run formato:aplicar` | Lo aplica.                                              |
| `npm run build`           | Compila el front con Vite.                              |
| `npm run docker:up`       | Levanta la demo completa en Docker.                     |

### Deuda pendiente de formato

El código PHP de este repositorio se escribió con tabuladores y sin tipado
estricto. La primera pasada de `composer estilo:aplicar` toca **unas 690 líneas
en 11 ficheros**. Prettier, más acotado, reformatea **3 ficheros del front**
(`index.html`, `demo.html` y `vite.config.js`).

Mientras esa pasada no se haga:

- Los pasos de **estilo** de la CI informan pero **no bloquean**
  (`continue-on-error: true` en `.github/workflows/ci.yml`).
- El análisis estático y la compilación **sí bloquean**.

Cuando se haga la limpieza, en un PR propio de tipo `style:` y sin ningún
cambio funcional dentro, hay que quitar esos `continue-on-error` y activar
`declare_strict_types` en `.php-cs-fixer.dist.php`.

---

## 2. Todo empieza por un issue

Nada se desarrolla sin issue, ni siquiera los cambios de una línea. El issue es
donde se discute *qué* hay que hacer; el PR es donde se discute *cómo* está
hecho. Mezclarlos hace que las decisiones se pierdan en hilos de revisión.

Hay tres plantillas y no se permiten issues en blanco:

- **Nueva funcionalidad** — algo que la demo no sabe hacer.
- **Error** — algo que no funciona como debería.
- **Tarea** — mantenimiento, documentación, refactor, CI, Docker.

Reglas:

- El título del issue lleva ya el prefijo de tipo (`feat:`, `fix:`, `chore:`…).
- Los **criterios de aceptación** son obligatorios y son una lista comprobable.
  La revisión del PR se hace contra esa lista.
- **Un issue, un asunto.** Si al escribirlo aparece un "y además", son dos issues.
- Si el cambio toca el **protocolo en el cable**, el issue va **primero** en
  `ip5-kyber-poc` y aquí se abre uno enlazado.
- Los fallos de **seguridad no van en un issue público**. Ver [`SECURITY.md`](SECURITY.md).

```bash
gh issue create --web
gh issue list
gh issue develop 42 --name feat/42-vista-de-bytes --base main --checkout
```

---

## 3. Ramas

Modelo **trunk-based**: `main` es siempre desplegable, y todo lo demás son ramas
cortas que viven poco. No hay `develop`, ni `release/*`.

**`main` está protegida en GitHub.** No se hace push directo: el servidor lo
rechaza. Además hay un hook local que da el aviso al instante, sin gastar un
viaje al servidor:

```bash
./scripts/instalar-hooks.sh    # hazlo una vez por clon
```

En `ip5-kyber-poc` ese hook no es un extra sino la única defensa, porque al ser
un repositorio privado con plan Free no admite protección de ramas.

### Nombre de la rama

```
<tipo>/<nº de issue>-<descripción-corta-en-kebab-case>
```

```
feat/42-vista-de-bytes-del-handshake
fix/57-no-registrar-el-secreto-en-consola
docs/61-documentar-el-arranque-en-docker
chore/63-actualizar-vite
```

Minúsculas, sin acentos ni `ñ`, separadas por guiones. El número de issue hace
que la rama siga siendo rastreable meses después.

### Ciclo de vida

```bash
git switch main
git pull
git switch -c feat/42-vista-de-bytes-del-handshake
# … trabajo, commits …
git push -u origin feat/42-vista-de-bytes-del-handshake
```

Una rama debería vivir **días, no semanas**. Si se alarga, el issue era
demasiado grande: pártelo.

Para mantenerla al día, mientras nadie más trabaje sobre ella:

```bash
git pull --rebase origin main
```

### Cuidado con el submódulo

`liboqs-php` es un submódulo, y es fácil incluirlo en un commit sin querer al
cambiar de rama o recompilar. **Antes de cada commit, comprueba que `git status`
no lo menciona.** Si aparece y no lo has actualizado a propósito:

```bash
git submodule update --init --recursive
```

Actualizar el submódulo es un cambio deliberado y va en su propio PR, de tipo
`build:`, explicando a qué versión se sube y por qué.

---

## 4. Commits

**Conventional Commits**, con la descripción en español:

```
<tipo>(<ámbito opcional>): <descripción en minúscula, en imperativo>

<cuerpo opcional: el porqué, no el qué>

<pie opcional: Refs #42, BREAKING CHANGE: …>
```

El **tipo** y `BREAKING CHANGE` van en inglés porque son etiquetas que leen las
herramientas. Todo lo demás, en español.

| Tipo       | Cuándo                                                        |
| ---------- | ------------------------------------------------------------- |
| `feat`     | Nueva funcionalidad visible desde fuera.                       |
| `fix`      | Corrección de un fallo.                                        |
| `docs`     | Solo documentación.                                            |
| `style`    | Formato, espacios, comas. Sin cambio de comportamiento.        |
| `refactor` | Reorganización interna sin cambiar el comportamiento.          |
| `perf`     | Mejora de rendimiento.                                         |
| `test`     | Añadir o corregir pruebas.                                     |
| `build`    | Dependencias, Docker, Vite, submódulos, empaquetado.           |
| `ci`       | Workflows de GitHub Actions.                                   |
| `chore`    | Tareas que no encajan arriba.                                  |
| `revert`   | Revertir un commit anterior.                                   |

Ámbitos habituales aquí: `demo`, `front`, `api`, `kem`, `cifrado`, `docker`,
`nginx`, `docs`.

Ejemplos:

```
feat(front): muestra las longitudes de clave en cada paso del handshake
fix(api): no registrar el secreto compartido en error_log
build(docker): fija la imagen de PHP a 8.3-fpm-alpine
docs: explica cómo inicializar el submódulo liboqs-php
```

Reglas prácticas:

- Descripción en **imperativo** ("añade", "corrige"), no en pasado.
- **Sin punto final** y, como norma, **menos de 72 caracteres** en la primera línea.
- Un commit = un cambio coherente. Si el mensaje necesita un "y", parte el commit.
- Los commits dentro de la rama pueden ser desordenados: el squash los funde.
  Lo que sí importa es el **título del PR**.

---

## 5. Pull request

### Abrirlo

```bash
gh pr create --fill --base main --web
```

- El **título del PR sigue Conventional Commits**. Con squash merge se convierte
  en el mensaje del commit de `main`. **La CI rechaza el PR si el título no
  cumple el formato.**
- El cuerpo se rellena con la plantilla. Lo importante es **`Closes #42`**.
- **Abre el PR en borrador** (`--draft`) si aún no está listo.
- Por encima de ~400 líneas de diff, pártelo. Un PR grande no se revisa: se
  aprueba a ciegas.
- Si el cambio se ve en pantalla, **adjunta una captura**. Es una demo: el
  aspecto es parte de la funcionalidad.

### Revisión

- **César abre un PR** → lo revisa Francisco. Siempre.
- **Francisco abre un PR** trabajando solo → puede auto-aprobarlo, pero el PR se
  abre igual: la CI tiene que pasar y el historial tiene que quedar registrado.
  Si toca `libs/kyber_utils.php`, `api_server/` o `app/`, espera revisión de
  César si está disponible.

Cómo se revisa:

- Contra los **criterios de aceptación del issue**.
- Comentarios concretos y accionables. Si es una preferencia y no un problema,
  ponle `nit:` delante.
- Quien recibe la revisión responde a **todos** los comentarios, aunque sea con
  "hecho". Los hilos los resuelve quien los abrió.
- Los cambios de la revisión van en **commits nuevos**, no en un `--amend`.

### Qué comprueba la CI

1. **Sintaxis** — `php -l` en PHP 8.1 y 8.4. *Bloquea.*
2. **Análisis estático** — PHPStan nivel 5. *Bloquea.*
3. **Compilación del front** — `npm run build`. *Bloquea.*
4. **Título del PR** — Conventional Commits. *Bloquea.*
5. **Estilo** — PHP-CS-Fixer y Prettier. *Informa, no bloquea todavía*
   (ver "Deuda pendiente de formato" más arriba).

### Mezclar

**Siempre _Squash and merge_.** Nunca *merge commit*, nunca *rebase and merge*.

Al mezclar:

1. Comprueba que el **mensaje del commit** es el título del PR y no la lista de
   commits de la rama. GitHub a veces mete la lista entera en el cuerpo: bórrala.
2. Deja el `Closes #42`.
3. **Borra la rama.**

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
```

Quien mezcla es **quien abrió el PR**, una vez aprobado y con la CI en verde.

---

## 6. Etiquetas

Las crea `scripts/configurar-github.sh`:

| Eje          | Etiquetas                                                                    |
| ------------ | ---------------------------------------------------------------------------- |
| **tipo**     | `tipo: funcionalidad`, `tipo: error`, `tipo: tarea`, `tipo: documentación`   |
| **área**     | `área: kem`, `área: cifrado`, `área: api`, `área: front`, `área: docker`, `área: infra` |
| **estado**   | `estado: bloqueado`, `estado: en revisión`, `estado: necesita diseño`         |
| **especial** | `protocolo`, `seguridad`, `buena primera tarea`                               |

`protocolo` es la importante: cualquier issue con esa etiqueta afecta también a
`ip5-kyber-poc` y necesita acuerdo de diseño previo.

---

## 7. Coordinación entre repositorios

- **`ip5-kyber-poc`** — implementación de referencia en PHP. Define el protocolo.
- **`kyber-demo`** — esta demo interactiva. Lo implementa y lo enseña.

Si un cambio afecta al formato en el cable: se abre el issue en **los dos**
repositorios y se enlazan entre sí
(`IP5-International-Platform-5/ip5-kyber-poc#12`). El de referencia va primero.

---

## 8. Ajustes del repositorio en GitHub

No se pueden versionar en ficheros: se aplican una vez con

```bash
./scripts/configurar-github.sh
```

Deja configurado: `main` protegida, PR obligatorio, CI obligatoria, squash como
única forma de mezclar, borrado automático de ramas y las etiquetas. Es
idempotente. Léelo antes de ejecutarlo: modifica los ajustes del repositorio en
GitHub.

Los hooks van aparte, porque son configuración de tu clon y no del remoto:

```bash
./scripts/instalar-hooks.sh
```

---

## 9. Chuleta

```bash
gh issue create --web                                  # 1. issue
gh issue develop 42 --name feat/42-lo-que-sea \
                    --base main --checkout             # 2. rama desde el issue
composer estilo:aplicar && composer verificar          # 3. antes de commitear
npm run formato:aplicar && npm run build
git status                                             #    ¿aparece liboqs-php?
git commit -m "feat(front): añade la vista de bytes"
git push -u origin feat/42-lo-que-sea
gh pr create --fill --base main --web                  # 4. PR
gh pr checks --watch                                   # 5. esperar a la CI
gh pr merge --squash --delete-branch                   # 6. mezclar
git switch main && git pull                            # 7. volver a main
```
