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
