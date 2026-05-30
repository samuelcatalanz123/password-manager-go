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
