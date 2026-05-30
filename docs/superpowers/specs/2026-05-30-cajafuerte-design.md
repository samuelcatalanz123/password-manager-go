# Diseño: CajaFuerte — Gestor de contraseñas de escritorio (Go + Fyne)

**Fecha:** 2026-05-30
**Estado:** Aprobado para escribir el plan de implementación
**Autor del proyecto:** Samuel (5º proyecto de portafolio)

## Objetivo

Una app de escritorio (ventana con botones) que guarda contraseñas **cifradas**
en la computadora. El usuario abre la app, escribe una **contraseña maestra**
que descifra su "caja fuerte", y puede ver, añadir, copiar y borrar entradas
(sitio · usuario · contraseña). Objetivo de aprendizaje: **criptografía aplicada**
(derivación de clave con Argon2, cifrado autenticado AES-GCM) y apps de escritorio
en Go.

> **Aviso (irá en el README y en la app):** proyecto educativo/portafolio. No
> sustituye a un gestor profesional auditado; no guardar contraseñas críticas
> reales.

## Decisiones tomadas (brainstorming)

| Tema      | Decisión                                                         |
| --------- | ---------------------------------------------------------------- |
| Funciones | Lo básico: maestra + lista + añadir/copiar/borrar (YAGNI)        |
| Forma     | App de **escritorio** (ventana), Go + **Fyne**                   |
| Cifrado   | Argon2id (derivar clave) + AES-256-GCM (cifrar la caja)          |
| Datos     | Un único archivo cifrado en disco                                |
| Repo      | Proyecto y repositorio **nuevos** (`password-manager-go`)        |

## Seguridad (el corazón del proyecto)

1. La contraseña maestra **no se guarda**. Se deriva una clave de 32 bytes con
   **Argon2id** usando una **sal** aleatoria de 16 bytes (guardada junto al
   archivo). Argon2 es lento a propósito → frena ataques de fuerza bruta.
2. La caja fuerte (lista de entradas en JSON) se cifra con **AES-256-GCM**
   (cifrado autenticado: si el archivo se altera o la clave es incorrecta, el
   descifrado falla de forma detectable).
3. Cada vez que se guarda, se usa un **nonce** aleatorio nuevo (12 bytes).
4. Formato del archivo: `salt(16) || nonce(12) || ciphertext`.
5. Contraseña maestra incorrecta = el `Open` de GCM falla → `ErrWrongPassword`.
   No hay recuperación posible (por diseño).

## Arquitectura y estructura

```
password-manager-go/
  go.mod / go.sum
  main.go                  Calcula la ruta del archivo, arranca la ventana Fyne.
  internal/vault/
    crypto.go              newSalt, deriveKey (Argon2id), encrypt/decrypt (AES-GCM).
    crypto_test.go         Pruebas: ida y vuelta, clave incorrecta, determinismo.
    vault.go               Entry, Vault; Create, Open, Save, Add, Delete; ErrWrongPassword.
    vault_test.go          Pruebas: crear+abrir, contraseña incorrecta, añadir/borrar.
  internal/ui/
    app.go                 Ventana Fyne: pantalla de login + pantalla de la lista.
  README.md
  .gitignore
  .github/workflows/ci.yml CI (build/vet/test del paquete vault).
```

### Paquete `vault` (lógica pura, 100% testeable sin ventana)

- `type Entry struct { Site, Username, Password string }`
- `type Vault struct { path string; salt, key []byte; Entries []Entry }`
- `var ErrWrongPassword = errors.New("contraseña incorrecta")`
- `func Create(path, master string) (*Vault, error)` — sal nueva, clave, caja
  vacía, guarda el archivo.
- `func Open(path, master string) (*Vault, error)` — lee el archivo, deriva la
  clave con la sal guardada, descifra; si falla → `ErrWrongPassword`.
- `func (v *Vault) Save() error` — cifra las entradas y reescribe el archivo.
- `func (v *Vault) Add(e Entry) error` — añade y guarda.
- `func (v *Vault) Delete(i int) error` — borra por índice y guarda.
- `func Exists(path string) bool` — ¿ya hay un archivo de caja?

crypto.go (funciones internas del paquete):
- `func newSalt() ([]byte, error)` — 16 bytes aleatorios (`crypto/rand`).
- `func deriveKey(master string, salt []byte) []byte` — `argon2.IDKey([]byte(master),
  salt, 1, 64*1024, 4, 32)`.
- `func encrypt(key, plaintext []byte) ([]byte, error)` — AES-GCM, devuelve
  `nonce || ciphertext`.
- `func decrypt(key, data []byte) ([]byte, error)` — separa el nonce y abre GCM.

### Paquete `ui` (capa fina sobre Fyne)

- `func Run(vaultPath string)` — crea `app.New()`, una ventana, y muestra:
  - **Login:** si `vault.Exists(path)` → pide la maestra para **abrir**; si no
    → pide crear una maestra nueva (con confirmación). Si la maestra es
    incorrecta, muestra el error y deja reintentar.
  - **Lista:** muestra las entradas (sitio · usuario). Botones: **Añadir**
    (diálogo con 3 campos), **Copiar** (copia la contraseña al portapapeles),
    **Borrar** (con confirmación).

## main.go

- Ruta del archivo: `filepath.Join(os.UserConfigDir(), "cajafuerte", "caja.vault")`
  (crea la carpeta si no existe). Configurable con la variable `VAULT_PATH`.
- Llama a `ui.Run(path)`.

## Manejo de errores

- Maestra incorrecta → mensaje "Contraseña incorrecta", reintentar.
- Primera vez (sin archivo) → flujo de **crear** maestra (pide escribirla dos
  veces; deben coincidir).
- Error de lectura/escritura del archivo → diálogo de error claro.

## Pruebas

- **crypto_test.go:** `encrypt`→`decrypt` recupera el texto; descifrar con clave
  distinta da error; `deriveKey` es determinista con la misma sal y cambia con
  otra sal.
- **vault_test.go:** `Create`+`Add`+`Open` (misma maestra) recupera las entradas;
  `Open` con maestra incorrecta → `ErrWrongPassword`; `Add`/`Delete` actualizan
  y persisten. Se usan archivos en `t.TempDir()`.
- `go build ./...`, `go vet ./...`, `go test ./...` limpios. (La ventana Fyne no
  se prueba automáticamente; la lógica de seguridad sí, a fondo.)

## Dependencias

- `fyne.io/fyne/v2` — interfaz gráfica de escritorio.
- `golang.org/x/crypto/argon2` — derivación de clave.
- (estándar) `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`.

## CI

GitHub Actions: `go build ./...`, `go vet ./...`, `go test ./...`. (Fyne necesita
librerías de sistema para compilar la GUI en Linux; si la CI da problemas con la
parte gráfica, se limita a `go test ./internal/vault/...`, que es la lógica de
seguridad.)

## Fuera de alcance (YAGNI)

Sincronización en la nube, compartir contraseñas, autocompletado en webs, app
móvil, generador de contraseñas, búsqueda. (Posibles mejoras futuras.)

## Criterios de éxito

1. `go run .` abre una ventana; la primera vez crea la maestra, luego la pide.
2. Se pueden añadir, copiar y borrar entradas, y persisten entre aperturas.
3. Con maestra incorrecta no se accede (descifrado falla limpiamente).
4. El archivo en disco está cifrado (ilegible sin la maestra).
5. Las pruebas de `vault` pasan (cifrado y persistencia).
6. El proyecto queda en su propio repositorio, listo para GitHub.
