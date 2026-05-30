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
