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
