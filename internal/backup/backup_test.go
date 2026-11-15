package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

// A control plane data directory with everything in it: CA, signing key, store, audit chain, decision archive.
func makeData(t *testing.T) (dir string, cert *x509.Certificate) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "cp-data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreateCA(dir, "test root", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateSigner(dir); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateTenant("acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	lg, err := audit.Open(filepath.Join(dir, "audit.jsonl"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"one", "two", "three"} {
		if _, err := lg.Append("acme", "owner", a, "x", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	lg.Close()
	arch, err := decisions.OpenArchive(filepath.Join(dir, "decisions"), decisions.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := arch.Append(broker.Record{Tenant: "acme", Kind: "private", Action: "allow", Event: "open", User: "alice", App: "erp", TS: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	arch.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := ca.Sign(key.Public(), pki.Identity{Tenant: "acme", Subject: "alice", Device: "d1", Role: pki.RoleDevice}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	return dir, cert
}

func TestBackupAndRestoreGiveBackTheSameControlPlane(t *testing.T) { // AGT-040 (GAP-REQ-01)
	dir, cert := makeData(t)
	out := filepath.Join(t.TempDir(), "b.tgz")
	m, err := Create(dir, out, time.Now(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("the backup holds keys, so its mode must be 0600, got %v", st.Mode().Perm())
	}
	have := map[string]bool{}
	for _, f := range m.Files {
		have[f.Path] = true
	}
	for _, want := range []string{"store.json", "ca.key", "ca.pem", "policy.key", "audit.jsonl"} {
		if !have[want] {
			t.Errorf("%s is not in the backup: %v", want, m.Files)
		}
	}
	if len(m.Files) < 6 {
		t.Errorf("the decision archive is not in the backup: %v", m.Files)
	}
	if _, err := Verify(out); err != nil {
		t.Fatal(err)
	}
	// the "disaster": the data is gone
	restored := filepath.Join(t.TempDir(), "new-cp-data")
	if _, moved, err := Restore(out, restored, false, time.Now(), nil); err != nil || moved != "" {
		t.Fatalf("%v %q", err, moved)
	}
	// the same CA came back, so a device certificate issued before still verifies
	ca2, err := pki.LoadOrCreateCA(restored, "would-be-new-name", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca2.Verify(cert, nil); err != nil {
		t.Errorf("a certificate issued before the loss no longer verifies: %v", err)
	}
	// the store, the audit chain and the archive are all there
	st2, err := store.Open(filepath.Join(restored, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Devices("acme"); err != nil {
		t.Errorf("the tenant is missing after the restore: %v", err)
	}
	if n, err := audit.Verify(filepath.Join(restored, "audit.jsonl")); err != nil || n != 3 {
		t.Errorf("audit chain: %d %v", n, err)
	}
	arch, err := decisions.OpenArchive(filepath.Join(restored, "decisions"), decisions.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	defer arch.Close()
	res, err := arch.Query("acme", decisions.Query{Limit: 100})
	if err != nil || len(res.Records) != 5 {
		t.Errorf("archive: %d records, %v", len(res.Records), err)
	}
	// files are private again
	if st, _ := os.Stat(filepath.Join(restored, "ca.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode %v", st.Mode().Perm())
	}
}

func TestRestoreRefusesToOverwriteAndMovesAsideOnlyWhenForced(t *testing.T) { // AGT-040
	dir, _ := makeData(t)
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Create(dir, out, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(t.TempDir(), "live")
	os.MkdirAll(existing, 0o700)
	os.WriteFile(filepath.Join(existing, "store.json"), []byte(`{"tenants":{}}`), 0o600)
	if _, _, err := Restore(out, existing, false, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("an existing directory must be refused: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(existing, "store.json")); string(b) != `{"tenants":{}}` {
		t.Fatal("a refused restore changed the live data")
	}
	_, moved, err := Restore(out, existing, true, time.Now(), nil)
	if err != nil || moved == "" {
		t.Fatalf("%v %q", err, moved)
	}
	if b, _ := os.ReadFile(filepath.Join(moved, "store.json")); string(b) != `{"tenants":{}}` {
		t.Error("the old data was not kept")
	}
	if _, err := os.Stat(filepath.Join(existing, "ca.key")); err != nil {
		t.Error("the new data is not in place")
	}
	left, _ := filepath.Glob(existing + ".restore-*")
	if len(left) != 0 {
		t.Errorf("staging left behind: %v", left)
	}
}

func TestDamagedOrAlteredBackupIsRefusedBeforeAnythingIsWritten(t *testing.T) { // AGT-040
	dir, _ := makeData(t)
	good := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Create(dir, good, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(good)
	target := filepath.Join(t.TempDir(), "never")
	try := func(name string, b []byte) {
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, b, 0o600)
		if _, err := Verify(p); err == nil {
			t.Errorf("%s: verify accepted it", name)
		}
		if _, _, err := Restore(p, target, false, time.Now(), nil); err == nil {
			t.Errorf("%s: restore accepted it", name)
		}
		if _, err := os.Stat(target); err == nil {
			t.Errorf("%s: something was written", name)
		}
		if g, _ := filepath.Glob(target + ".restore-*"); len(g) != 0 {
			t.Errorf("%s: staging left behind", name)
		}
	}
	try("truncated", raw[:len(raw)/2])
	try("not-gzip", []byte("hello"))
	flip := append([]byte(nil), raw...)
	flip[len(flip)/2] ^= 0xff
	try("flipped-byte", flip)

	// an altered file with a valid archive structure: change store.json but keep the old manifest
	rewrite := func(name string, mod func(h *tar.Header, b []byte) (string, []byte, bool), extra func(tw *tar.Writer)) {
		in, _ := os.Open(good)
		gz, _ := gzip.NewReader(in)
		tr := tar.NewReader(gz)
		p := filepath.Join(t.TempDir(), name)
		o, _ := os.Create(p)
		gw := gzip.NewWriter(o)
		tw := tar.NewWriter(gw)
		type ent struct {
			h *tar.Header
			b []byte
		}
		var all []ent
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			b := make([]byte, h.Size)
			tr.Read(b)
			for n := 0; n < len(b); {
				k, err := tr.Read(b[n:])
				n += k
				if err != nil {
					break
				}
			}
			all = append(all, ent{h, b})
		}
		in.Close()
		for _, e := range all {
			n, b, keep := mod(e.h, e.b)
			if !keep {
				continue
			}
			h := *e.h
			h.Name, h.Size = n, int64(len(b))
			tw.WriteHeader(&h)
			tw.Write(b)
		}
		if extra != nil {
			extra(tw)
		}
		tw.Close()
		gw.Close()
		o.Close()
		raw2, _ := os.ReadFile(p)
		try(name, raw2)
	}
	rewrite("altered-content", func(h *tar.Header, b []byte) (string, []byte, bool) {
		if h.Name == "store.json" {
			return h.Name, []byte(`{"tenants":{"evil":{}}}`), true
		}
		return h.Name, b, true
	}, nil)
	rewrite("missing-ca-key", func(h *tar.Header, b []byte) (string, []byte, bool) { return h.Name, b, h.Name != "ca.key" }, nil)
	rewrite("path-traversal", func(h *tar.Header, b []byte) (string, []byte, bool) {
		if h.Name == "audit.jsonl" {
			return "../escape.jsonl", b, true
		}
		return h.Name, b, true
	}, nil)
	rewrite("absolute-path", func(h *tar.Header, b []byte) (string, []byte, bool) {
		if h.Name == "audit.jsonl" {
			return "/tmp/escape.jsonl", b, true
		}
		return h.Name, b, true
	}, nil)
	rewrite("extra-file-not-in-manifest", func(h *tar.Header, b []byte) (string, []byte, bool) {
		if h.Name == manifestName {
			return "", nil, false
		}
		return h.Name, b, true
	}, func(tw *tar.Writer) {})
}

func TestBackupCutsLogsAtTheLastCompleteLineAndRefusesBadInput(t *testing.T) { // AGT-040
	dir, _ := makeData(t)
	// a record being written while the backup runs: a half line at the end of the audit log
	f, _ := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":4,"half`)
	f.Close()
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Create(dir, out, time.Now(), "t"); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "r")
	if _, _, err := Restore(out, restored, false, time.Now(), nil); err != nil {
		t.Fatalf("the half line broke the restore: %v", err)
	}
	if n, err := audit.Verify(filepath.Join(restored, "audit.jsonl")); err != nil || n != 3 {
		t.Errorf("%d %v", n, err)
	}
	// the live directory is not changed by a backup
	b, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !strings.HasSuffix(string(b), `"half`) {
		t.Error("the backup changed the live log")
	}
	// not a data directory, and an output inside the directory, are refused
	if _, err := Create(t.TempDir(), filepath.Join(t.TempDir(), "x"), time.Now(), "t"); err == nil {
		t.Error("an empty directory was accepted")
	}
	if _, err := Create(dir, filepath.Join(dir, "inside.tgz"), time.Now(), "t"); err == nil {
		t.Error("an output inside the data directory was accepted")
	}
	// a symbolic link in the directory is refused, not followed
	os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	if _, err := Create(dir, filepath.Join(t.TempDir(), "y"), time.Now(), "t"); err == nil {
		t.Error("a link was accepted")
	}
	if _, err := os.Stat(filepath.Join(os.TempDir(), "y.tmp")); err == nil {
		t.Error("a temporary file was left")
	}
}

// A data directory made with a master key: nothing private is in clear on disk, in the backup, or after a restore.
func makeSealed(t *testing.T, k *seal.Key) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cp-data")
	os.MkdirAll(dir, 0o700)
	if _, err := pki.LoadOrCreateCAKey(dir, "root", nil, k); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateSignerKey(dir, k); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithKey(filepath.Join(dir, "store.json"), k)
	if err != nil {
		t.Fatal(err)
	}
	st.CreateTenant("acme", "Acme")
	if err := st.PutSecret("acme", store.Secret{Name: "crm", Host: "crm.example", Header: "Authorization", Value: "Bearer hunter2-secret-value"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetInspection("acme", true, nil); err != nil { // makes the tenant's inspection CA key
		t.Fatal(err)
	}
	return dir
}

func anyContains(t *testing.T, root, needle string) []string {
	var hits []string
	filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), needle) {
				hits = append(hits, p)
			}
		}
		return nil
	})
	return hits
}

func TestSealedDataIsNotInClearOnDiskInTheBackupOrAfterARestore(t *testing.T) { // AGT-041 (GAP-REQ-02)
	k, wrong := mustKey(t), mustKey(t)
	dir := makeSealed(t, k)
	for _, needle := range []string{"hunter2-secret-value", "PRIVATE KEY"} {
		if h := anyContains(t, dir, needle); len(h) != 0 {
			t.Fatalf("%q is in clear in %v", needle, h)
		}
	}
	// the store and the keys open with the key, and not without it or with another
	if _, err := store.OpenWithKey(filepath.Join(dir, "store.json"), k); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(filepath.Join(dir, "store.json")); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Errorf("a sealed store opened without a key, or the message does not say what to do: %v", err)
	}
	if _, err := store.OpenWithKey(filepath.Join(dir, "store.json"), wrong); err == nil {
		t.Error("a sealed store opened with the wrong key")
	}
	if _, err := pki.LoadOrCreateCAKey(dir, "root", nil, nil); err == nil {
		t.Error("a sealed CA key was replaced by a new one instead of refusing: that would orphan every certificate")
	}
	if _, err := pki.LoadOrCreateSignerKey(dir, wrong); err == nil {
		t.Error("a sealed signing key opened with the wrong key")
	}
	ca1, _ := pki.LoadOrCreateCAKey(dir, "root", nil, k)
	ca2, _ := pki.LoadOrCreateCAKey(dir, "root", nil, k)
	if !ca1.Cert.Equal(ca2.Cert) {
		t.Error("the CA changed between two loads")
	}
	// the backup copies the sealed files as they are (checked after the restore below: gzip would hide a leak here)
	out := filepath.Join(t.TempDir(), "b.tgz")
	if _, err := Create(dir, out, time.Now(), "t"); err != nil {
		t.Fatal(err)
	}
	// restore: refused without the key or with the wrong one, nothing written; fine with the right one
	target := filepath.Join(t.TempDir(), "new")
	for name, key := range map[string]*seal.Key{"no key": nil, "wrong key": wrong} {
		if _, _, err := Restore(out, target, false, time.Now(), key); err == nil {
			t.Errorf("%s: restore accepted", name)
		}
		if _, err := os.Stat(target); err == nil {
			t.Errorf("%s: something was written", name)
		}
	}
	if _, _, err := Restore(out, target, false, time.Now(), k); err != nil {
		t.Fatal(err)
	}
	if h := anyContains(t, target, "hunter2-secret-value"); len(h) != 0 {
		t.Errorf("after the restore the secret is in clear in %v", h)
	}
	st, err := store.OpenWithKey(filepath.Join(target, "store.json"), k)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := st.Secret("acme", "crm"); !ok || got.Value != "Bearer hunter2-secret-value" {
		t.Errorf("the secret did not survive: %+v %v", got, ok)
	}
}

func mustKey(t *testing.T) *seal.Key {
	k, err := seal.ParseKey(seal.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPlainDataIsSealedOnceAndKeepsWorking(t *testing.T) { // AGT-041
	dir, cert := makeData(t) // made in clear, as an installation from before this feature
	if h := anyContains(t, dir, "PRIVATE KEY"); len(h) == 0 {
		t.Fatal("the fixture should start in clear")
	}
	k := mustKey(t)
	for _, f := range []string{"ca.key", "policy.key", "store.json"} {
		if changed, err := seal.SealInPlace(filepath.Join(dir, f), k); err != nil || !changed {
			t.Fatalf("%s: %v %v", f, changed, err)
		}
	}
	if h := anyContains(t, dir, "PRIVATE KEY"); len(h) != 0 {
		t.Errorf("still in clear: %v", h)
	}
	ca, err := pki.LoadOrCreateCAKey(dir, "root", nil, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Verify(cert, nil); err != nil {
		t.Errorf("a certificate issued before the encryption no longer verifies: %v", err)
	}
	if _, err := store.OpenWithKey(filepath.Join(dir, "store.json"), k); err != nil {
		t.Fatal(err)
	}
}
