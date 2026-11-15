package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

func mk(t *testing.T) *seal.Key {
	k, err := seal.ParseKey(seal.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The master key can be replaced, also after an interruption half way, and nothing is lost (GAP-REQ-05).
func TestMasterKeyCanBeReplaced(t *testing.T) { // AGT-042
	dir := t.TempDir()
	oldK, newK, other := mk(t), mk(t), mk(t)
	ca1, err := pki.LoadOrCreateCAKey(dir, "root", nil, oldK)
	if err != nil {
		t.Fatal(err)
	}
	pki.LoadOrCreateSignerKey(dir, oldK)
	st, _ := store.OpenWithKey(filepath.Join(dir, "store.json"), oldK)
	st.CreateTenant("acme", "Acme")
	st.PutSecret("acme", store.Secret{Name: "crm", Host: "h", Header: "X", Value: "v-secret"})

	if _, err := rekey(dir, other, newK); err == nil {
		t.Fatal("a rekey with a key that does not open the files was accepted")
	}
	if _, err := pki.LoadOrCreateCAKey(dir, "root", nil, oldK); err != nil {
		t.Fatalf("a refused rekey damaged the files: %v", err)
	}
	// an interruption after the first file: ca.key is under the new key, the other two still under the old one
	p := filepath.Join(dir, "ca.key")
	plain, _ := seal.Read(p, oldK)
	seal.Write(p, plain, newK)
	n, err := rekey(dir, oldK, newK)
	if err != nil || n != 3 {
		t.Fatalf("finishing an interrupted rekey: %d %v", n, err)
	}
	if n, err := rekey(dir, oldK, newK); err != nil || n != 3 {
		t.Fatalf("running it again must change nothing and not fail: %d %v", n, err)
	}
	// everything opens with the new key and nothing with the old
	ca2, err := pki.LoadOrCreateCAKey(dir, "root", nil, newK)
	if err != nil || !ca2.Cert.Equal(ca1.Cert) {
		t.Fatalf("the CA changed or does not open: %v", err)
	}
	if _, err := pki.LoadOrCreateSignerKey(dir, newK); err != nil {
		t.Fatal(err)
	}
	st2, err := store.OpenWithKey(filepath.Join(dir, "store.json"), newK)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := st2.Secret("acme", "crm"); !ok || s.Value != "v-secret" {
		t.Errorf("the secret did not survive: %+v", s)
	}
	for _, f := range []string{"ca.key", "policy.key", "store.json"} {
		if _, err := seal.Read(filepath.Join(dir, f), oldK); err == nil {
			t.Errorf("%s still opens with the old key", f)
		}
		if st, _ := os.Stat(filepath.Join(dir, f)); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
	}
	if left, _ := filepath.Glob(dir + "/*.tmp"); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	// plain files are not "re-keyed": it says to start with the key once
	plainDir := t.TempDir()
	os.WriteFile(filepath.Join(plainDir, "ca.key"), []byte("x"), 0o600)
	if _, err := rekey(plainDir, oldK, newK); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Errorf("a clear file: %v", err)
	}
}
