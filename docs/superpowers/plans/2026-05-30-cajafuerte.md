# CajaFuerte — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** App de escritorio en Go (Fyne) que guarda contraseñas cifradas (Argon2id + AES-256-GCM).

**Architecture:** Paquete `vault` con la lógica de cifrado y persistencia (testeada a fondo) y paquete `ui` (capa fina sobre Fyne). `main.go` calcula la ruta del archivo y arranca la ventana.

**Tech Stack:** Go 1.26 · `fyne.io/fyne/v2` · `golang.org/x/crypto/argon2` · crypto/aes, crypto/cipher.

Módulo: `github.com/samuelcatalanz123/password-manager-go`

**Commits:** `git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "..."`
Verificación: `go build ./... && go vet ./... && go test ./...`

---

## File Structure

```
password-manager-go/
  go.mod / go.sum
  main.go
  .gitignore
  README.md
  .github/workflows/ci.yml
  internal/vault/
    crypto.go / crypto_test.go
    vault.go  / vault_test.go
  internal/ui/
    app.go
```

---

### Task 1: Scaffold (módulo, git, dependencias)

- [ ] **Step 1: git + módulo**
```bash
cd /Users/mqr93ea/Repos/password-manager-go
git init
go mod init github.com/samuelcatalanz123/password-manager-go
```
- [ ] **Step 2: `.gitignore`**
```
/password-manager-go
*.vault
*.test
.DS_Store
```
- [ ] **Step 3: dependencias**
```bash
go get golang.org/x/crypto/argon2
go get fyne.io/fyne/v2
```
- [ ] **Step 4: commit**
```bash
git add -A
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "chore: inicializar módulo y dependencias (Fyne, x/crypto)"
```

---

### Task 2: Cifrado (TDD) — `internal/vault/crypto.go`

- [ ] **Step 1: test que falla** — `internal/vault/crypto_test.go`
```go
package vault

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	salt, _ := newSalt()
	key := deriveKey("maestra-secreta", salt)
	msg := []byte("hola mundo secreto")
	enc, err := encrypt(key, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := decrypt(key, enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, msg) {
		t.Fatalf("esperaba %q, obtuve %q", msg, dec)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	salt, _ := newSalt()
	enc, _ := encrypt(deriveKey("buena", salt), []byte("datos"))
	if _, err := decrypt(deriveKey("mala", salt), enc); err == nil {
		t.Fatal("esperaba error al descifrar con clave incorrecta")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt, _ := newSalt()
	if !bytes.Equal(deriveKey("x", salt), deriveKey("x", salt)) {
		t.Error("misma maestra + misma sal debería dar la misma clave")
	}
	other, _ := newSalt()
	if bytes.Equal(deriveKey("x", salt), deriveKey("x", other)) {
		t.Error("distinta sal debería dar distinta clave")
	}
}
```
- [ ] **Step 2: ver fallar** — `go test ./internal/vault/` → FAIL (undefined)
- [ ] **Step 3: implementar** — `internal/vault/crypto.go`
```go
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16
	keyLen  = 32
)

// newSalt genera una sal aleatoria de 16 bytes.
func newSalt() ([]byte, error) {
	s := make([]byte, saltLen)
	_, err := rand.Read(s)
	return s, err
}

// deriveKey transforma la contraseña maestra en una clave de 32 bytes con Argon2id.
func deriveKey(master string, salt []byte) []byte {
	return argon2.IDKey([]byte(master), salt, 1, 64*1024, 4, keyLen)
}

// encrypt cifra plaintext con AES-256-GCM y devuelve nonce || ciphertext.
func encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt separa el nonce y descifra; falla si la clave es incorrecta o los datos están alterados.
func decrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("datos cifrados demasiado cortos")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
```
- [ ] **Step 4: ver pasar** — `go test ./internal/vault/` → PASS
- [ ] **Step 5: commit**
```bash
git add internal/vault/crypto.go internal/vault/crypto_test.go
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "feat: cifrado AES-GCM + derivación Argon2id con pruebas"
```

---

### Task 3: Caja fuerte (TDD) — `internal/vault/vault.go`

- [ ] **Step 1: test que falla** — `internal/vault/vault_test.go`
```go
package vault

import (
	"errors"
	"path/filepath"
	"testing"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "caja.vault")
}

func TestCreateAddAndReopen(t *testing.T) {
	path := tempPath(t)
	v, err := Create(path, "maestra")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Add(Entry{Site: "github.com", Username: "sam", Password: "p4ss"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Reabrir con la misma maestra
	v2, err := Open(path, "maestra")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(v2.Entries) != 1 || v2.Entries[0].Site != "github.com" || v2.Entries[0].Password != "p4ss" {
		t.Fatalf("entradas mal recuperadas: %+v", v2.Entries)
	}
}

func TestOpenWrongPassword(t *testing.T) {
	path := tempPath(t)
	if _, err := Create(path, "buena"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Open(path, "mala"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("esperaba ErrWrongPassword, obtuve %v", err)
	}
}

func TestDelete(t *testing.T) {
	path := tempPath(t)
	v, _ := Create(path, "m")
	_ = v.Add(Entry{Site: "a"})
	_ = v.Add(Entry{Site: "b"})
	if err := v.Delete(0); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(v.Entries) != 1 || v.Entries[0].Site != "b" {
		t.Fatalf("borrado incorrecto: %+v", v.Entries)
	}
}

func TestExists(t *testing.T) {
	path := tempPath(t)
	if Exists(path) {
		t.Error("no debería existir todavía")
	}
	_, _ = Create(path, "m")
	if !Exists(path) {
		t.Error("debería existir tras Create")
	}
}
```
- [ ] **Step 2: ver fallar** — `go test ./internal/vault/` → FAIL (undefined)
- [ ] **Step 3: implementar** — `internal/vault/vault.go`
```go
// Package vault cifra y guarda en disco una lista de contraseñas.
package vault

import (
	"encoding/json"
	"errors"
	"os"
)

// ErrWrongPassword indica que la contraseña maestra no es correcta.
var ErrWrongPassword = errors.New("contraseña incorrecta")

// Entry es una contraseña guardada.
type Entry struct {
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Vault es la caja fuerte: entradas en memoria + cómo cifrarlas y guardarlas.
type Vault struct {
	path    string
	salt    []byte
	key     []byte
	Entries []Entry
}

// Exists indica si ya hay un archivo de caja en path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create crea una caja vacía con una sal nueva y la guarda cifrada.
func Create(path, master string) (*Vault, error) {
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, salt: salt, key: deriveKey(master, salt)}
	if err := v.Save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open lee el archivo, deriva la clave con la sal guardada y descifra las entradas.
func Open(path, master string) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < saltLen {
		return nil, errors.New("archivo de caja corrupto")
	}
	salt, body := raw[:saltLen], raw[saltLen:]
	key := deriveKey(master, salt)
	plain, err := decrypt(key, body)
	if err != nil {
		return nil, ErrWrongPassword
	}
	var entries []Entry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, err
	}
	return &Vault{path: path, salt: salt, key: key, Entries: entries}, nil
}

// Save cifra las entradas y reescribe el archivo (salt || nonce || ciphertext).
func (v *Vault) Save() error {
	plain, err := json.Marshal(v.Entries)
	if err != nil {
		return err
	}
	body, err := encrypt(v.key, plain)
	if err != nil {
		return err
	}
	out := append(append([]byte{}, v.salt...), body...)
	return os.WriteFile(v.path, out, 0o600)
}

// Add añade una entrada y guarda.
func (v *Vault) Add(e Entry) error {
	v.Entries = append(v.Entries, e)
	return v.Save()
}

// Delete borra la entrada en el índice i y guarda.
func (v *Vault) Delete(i int) error {
	if i < 0 || i >= len(v.Entries) {
		return errors.New("índice fuera de rango")
	}
	v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
	return v.Save()
}
```
- [ ] **Step 4: ver pasar** — `go test ./internal/vault/` → PASS (todos)
- [ ] **Step 5: commit**
```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "feat: caja fuerte (crear/abrir/añadir/borrar) cifrada en disco"
```

---

### Task 4: Interfaz Fyne — `internal/ui/app.go`

**Files:** Create `internal/ui/app.go`

- [ ] **Step 1: implementar la ventana**

`internal/ui/app.go` (login → lista; usa diálogos para añadir/borrar):
```go
// Package ui contiene la ventana de escritorio (Fyne) de CajaFuerte.
package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelcatalanz123/password-manager-go/internal/vault"
)

// Run arranca la app de escritorio usando el archivo de caja en vaultPath.
func Run(vaultPath string) {
	a := app.New()
	w := a.NewWindow("CajaFuerte 🔐")
	w.Resize(fyne.NewSize(420, 480))
	showLogin(w, vaultPath)
	w.ShowAndRun()
}

// showLogin muestra la pantalla para crear o introducir la maestra.
func showLogin(w fyne.Window, path string) {
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Contraseña maestra")
	info := widget.NewLabel("")

	first := !vault.Exists(path)
	title := "Introduce tu contraseña maestra"
	btnText := "Abrir"
	if first {
		title = "Crea tu contraseña maestra (no la olvides)"
		btnText = "Crear"
	}

	action := func() {
		if pass.Text == "" {
			info.SetText("Escribe una contraseña.")
			return
		}
		var v *vault.Vault
		var err error
		if first {
			v, err = vault.Create(path, pass.Text)
		} else {
			v, err = vault.Open(path, pass.Text)
		}
		if err != nil {
			info.SetText("Contraseña incorrecta.")
			return
		}
		showList(w, v)
	}
	pass.OnSubmitted = func(string) { action() }

	form := container.NewVBox(
		widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		pass,
		widget.NewButton(btnText, action),
		info,
	)
	w.SetContent(container.NewPadded(form))
}

// showList muestra las entradas con botones añadir/copiar/borrar.
func showList(w fyne.Window, v *vault.Vault) {
	var list *widget.List
	list = widget.NewList(
		func() int { return len(v.Entries) },
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			e := v.Entries[i]
			o.(*widget.Label).SetText(e.Site + "  —  " + e.Username)
		},
	)

	selected := -1
	list.OnSelected = func(i widget.ListItemID) { selected = i }

	addBtn := widget.NewButton("➕ Añadir", func() {
		site := widget.NewEntry()
		user := widget.NewEntry()
		pw := widget.NewPasswordEntry()
		items := []*widget.FormItem{
			widget.NewFormItem("Sitio", site),
			widget.NewFormItem("Usuario", user),
			widget.NewFormItem("Contraseña", pw),
		}
		dialog.ShowForm("Nueva entrada", "Guardar", "Cancelar", items, func(ok bool) {
			if !ok || site.Text == "" {
				return
			}
			if err := v.Add(vault.Entry{Site: site.Text, Username: user.Text, Password: pw.Text}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			list.Refresh()
		}, w)
	})

	copyBtn := widget.NewButton("📋 Copiar contraseña", func() {
		if selected < 0 || selected >= len(v.Entries) {
			dialog.ShowInformation("Copiar", "Selecciona una entrada primero.", w)
			return
		}
		w.Clipboard().SetContent(v.Entries[selected].Password)
		dialog.ShowInformation("Copiado", "Contraseña copiada al portapapeles.", w)
	})

	delBtn := widget.NewButton("🗑️ Borrar", func() {
		if selected < 0 || selected >= len(v.Entries) {
			dialog.ShowInformation("Borrar", "Selecciona una entrada primero.", w)
			return
		}
		dialog.ShowConfirm("Borrar", "¿Borrar esta entrada?", func(ok bool) {
			if !ok {
				return
			}
			if err := v.Delete(selected); err != nil {
				dialog.ShowError(err, w)
				return
			}
			selected = -1
			list.UnselectAll()
			list.Refresh()
		}, w)
	})

	buttons := container.NewHBox(addBtn, copyBtn, delBtn)
	w.SetContent(container.NewBorder(
		widget.NewLabelWithStyle("Tus contraseñas", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		buttons, nil, nil, list,
	))
}
```

- [ ] **Step 2: verificar compilación**
Run: `go build ./...`
Expected: compila (puede tardar la 1ª vez por Fyne). Si alguna llamada de Fyne
cambió de nombre en la versión instalada, ajustarla siguiendo el error.

- [ ] **Step 3: commit**
```bash
git add internal/ui/app.go
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "feat: interfaz de escritorio Fyne (login + lista + añadir/copiar/borrar)"
```

---

### Task 5: main.go

- [ ] **Step 1: implementar `main.go`**
```go
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/samuelcatalanz123/password-manager-go/internal/ui"
)

func main() {
	ui.Run(vaultPath())
}

// vaultPath devuelve la ruta del archivo de caja (configurable con VAULT_PATH).
func vaultPath() string {
	if p := os.Getenv("VAULT_PATH"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dir = filepath.Join(dir, "cajafuerte")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("no se pudo crear la carpeta de datos: %v", err)
	}
	return filepath.Join(dir, "caja.vault")
}
```
- [ ] **Step 2: verificar todo**
Run: `go build ./... && go vet ./... && go test ./...`
Expected: compila, vet limpio, tests del paquete `vault` PASS.
- [ ] **Step 3: commit**
```bash
git add main.go
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "feat: punto de entrada main (ruta del archivo de caja)"
```

---

### Task 6: README + CI

- [ ] **Step 1: `README.md`**
```markdown
# CajaFuerte — Gestor de contraseñas de escritorio (Go + Fyne)

App de escritorio que guarda tus contraseñas **cifradas** en tu computadora.
Una sola **contraseña maestra** descifra tu "caja fuerte". Hecha en **Go** con
**Fyne** (interfaz gráfica). Cifrado: **Argon2id** (derivación de clave) +
**AES-256-GCM** (cifrado autenticado).

> ⚠️ Proyecto educativo/portafolio. No sustituye a un gestor profesional
> auditado; no guardes contraseñas críticas reales.

## Uso

```bash
go run .
```

La primera vez te pide **crear** una contraseña maestra; después te la pide para
**abrir**. Puedes añadir, copiar y borrar entradas. Los datos se guardan
cifrados en `caja.vault` (en la carpeta de configuración del usuario; se puede
cambiar con la variable `VAULT_PATH`).

## Cómo funciona la seguridad

- La maestra no se guarda: se deriva una clave de 32 bytes con **Argon2id** y
  una sal aleatoria.
- La lista de contraseñas se cifra con **AES-256-GCM** (si la maestra es
  incorrecta o el archivo se altera, el descifrado falla).
- Formato del archivo: `salt(16) || nonce(12) || datos cifrados`.

## Estructura

```
main.go                 arranque (ruta del archivo, lanza la ventana)
internal/vault/         cifrado y persistencia (con pruebas)
internal/ui/            la ventana (Fyne)
```

## Pruebas

```bash
go test ./...
```

Las pruebas cubren a fondo la **seguridad** (cifrar/descifrar, contraseña
incorrecta, guardar/cargar). La interfaz gráfica es una capa fina encima.

## Stack

Go (crypto/aes, crypto/cipher, crypto/rand, encoding/json) ·
Argon2id (golang.org/x/crypto) · Fyne (fyne.io/fyne/v2).
```
- [ ] **Step 2: `.github/workflows/ci.yml`**
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Test (lógica de seguridad)
        run: go test ./internal/vault/...
```
> La CI prueba el paquete `vault` (la seguridad). La GUI de Fyne necesita
> librerías de sistema para compilar en Linux, así que no se compila en CI.
- [ ] **Step 3: commit**
```bash
git add README.md .github docs
git -c user.name="Samuel Catalán" -c user.email="samuelcatalanz123@gmail.com" commit -m "docs: README y CI"
```

---

### Task 7: Prueba manual

- [ ] Run `go run .` → crear maestra → añadir una entrada → cerrar → reabrir con
  la maestra → la entrada sigue ahí. Comprobar que `caja.vault` es ilegible
  (binario cifrado). Comprobar que con otra maestra no abre.

---

## Self-Review

- **Cobertura:** cifrado (T2), persistencia/caja (T3), GUI (T4), arranque (T5),
  README+CI (T6), prueba manual (T7). ✔
- **Sin placeholders:** todo el código está escrito. ✔
- **Consistencia de tipos:** `Entry{Site,Username,Password}`, `Vault` con
  `Create/Open/Save/Add/Delete/Exists`, `ErrWrongPassword`, `ui.Run(path)` —
  usados igual en tests, UI y main. Funciones de crypto (`newSalt/deriveKey/
  encrypt/decrypt`) coinciden con sus pruebas. ✔
- **Riesgo conocido:** nombres de la API de Fyne pueden variar según versión
  (p. ej. `w.Clipboard()`); ajustar al compilar siguiendo el mensaje de error.
