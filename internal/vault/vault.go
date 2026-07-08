// Package vault cifra y guarda en disco una lista de contraseñas.
package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// Save cifra las entradas y reescribe el archivo de forma ATÓMICA: escribe
// primero en un temporal (misma carpeta), lo vuelca a disco y luego lo renombra
// encima del original. Así, si se corta la luz a mitad, la caja nunca queda
// corrupta: o queda entera la vieja, o entera la nueva. (salt || nonce || ciphertext)
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

	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".caja-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // si algo falla antes del rename, no dejamos basura

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // asegura que esté en disco antes de renombrar
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, v.path) // renombrar es atómico
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
