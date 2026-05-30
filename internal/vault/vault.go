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
