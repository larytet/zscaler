package seal

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(t *testing.T) *Key {
	t.Helper()
	k, err := ParseKey(Generate())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealRoundTripAndWhatItRefuses(t *testing.T) { // AGT-041 (GAP-REQ-02)
	k, other := key(t), key(t)
	plain := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n")
	s := k.Seal("ca.key", plain)
	if bytes.Contains(s, []byte("secret")) || !IsSealed(s) || IsSealed(plain) {
		t.Fatal("the sealed form shows the content or is not marked")
	}
	if got, err := k.Open("ca.key", s); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("%v %q", err, got)
	}
	if bytes.Equal(k.Seal("ca.key", plain), s) {
		t.Error("two seals of the same content must differ (fresh nonce)")
	}
	if _, err := other.Open("ca.key", s); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a wrong key: %v", err)
	}
	if _, err := k.Open("policy.key", s); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a sealed file renamed to another file must not open: %v", err)
	}
	if _, err := (*Key)(nil).Open("ca.key", s); !errors.Is(err, ErrNeedKey) {
		t.Errorf("no key: %v", err)
	}
	for i := len(magic); i < len(s); i += 7 { // any changed byte, in the nonce or the content, is found
		c := append([]byte(nil), s...)
		c[i] ^= 1
		if _, err := k.Open("ca.key", c); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("byte %d changed and the file still opened: %v", i, err)
		}
	}
	if _, err := k.Open("ca.key", s[:len(s)-3]); err == nil {
		t.Error("a truncated file opened")
	}
	if _, err := k.Open("ca.key", s[:len(magic)+2]); err == nil {
		t.Error("a file cut short opened")
	}
}

func TestParseKeyForms(t *testing.T) { // AGT-041
	raw := bytes.Repeat([]byte{7}, 32)
	for name, s := range map[string]string{
		"hex": hex.EncodeToString(raw), "std": base64.StdEncoding.EncodeToString(raw), "raw-std": base64.RawStdEncoding.EncodeToString(raw),
		"url": base64.URLEncoding.EncodeToString(raw), "raw-url": base64.RawURLEncoding.EncodeToString(raw), "spaces": "  " + hex.EncodeToString(raw) + "\n",
	} {
		k, err := ParseKey(s)
		if err != nil || k.b != [32]byte(raw) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 63), base64.StdEncoding.EncodeToString(raw[:16]), base64.StdEncoding.EncodeToString(append(raw, 1))} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	g1, g2 := Generate(), Generate()
	if g1 == g2 {
		t.Error("two generated keys are equal")
	}
}

func TestFilesSealedInPlaceAndReadBack(t *testing.T) { // AGT-041
	dir := t.TempDir()
	p := filepath.Join(dir, "store.json")
	k := key(t)
	if changed, err := SealInPlace(p, k); err != nil || changed {
		t.Fatalf("a missing file is not an error and changes nothing: %v %v", changed, err)
	}
	os.WriteFile(p, []byte(`{"secret":"hunter2"}`), 0o644)
	if changed, err := SealInPlace(p, k); err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("hunter2")) {
		t.Fatal("still in clear")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if changed, err := SealInPlace(p, k); err != nil || changed {
		t.Errorf("sealing twice must change nothing: %v %v", changed, err)
	}
	if _, err := SealInPlace(p, key(t)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a wrong key must be found at start-up: %v", err)
	}
	if b, err := Read(p, k); err != nil || string(b) != `{"secret":"hunter2"}` {
		t.Fatalf("%v %s", err, b)
	}
	if _, err := Read(p, nil); !errors.Is(err, ErrNeedKey) {
		t.Errorf("%v", err)
	}
	// a plain file is read as it is, with or without a key
	q := filepath.Join(dir, "plain")
	os.WriteFile(q, []byte("x"), 0o600)
	if b, err := Read(q, k); err != nil || string(b) != "x" {
		t.Errorf("%v %s", err, b)
	}
	if left, _ := filepath.Glob(dir + "/*.tmp"); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
