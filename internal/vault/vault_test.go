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
