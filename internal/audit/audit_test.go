package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fill(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append("t1", "admin", "policy.update", "private", map[string]int{"v": i}, map[string]int{"v": i + 1}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
}

func TestChainVerifies(t *testing.T) { // AUD-001, CP-012
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	fill(t, p, 5)
	if n, err := Verify(p); err != nil || n != 5 {
		t.Fatalf("%d %v", n, err)
	}
	fill(t, p, 3) // reopen and continue the chain
	if n, err := Verify(p); err != nil || n != 8 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestTamperDetected(t *testing.T) { // AUD-001, SEC-020
	for name, mutate := range map[string]func([]string) []string{
		"alter":    func(l []string) []string { l[2] = strings.Replace(l[2], `"admin"`, `"mallory"`, 1); return l },
		"delete":   func(l []string) []string { return append(l[:2], l[3:]...) },
		"reorder":  func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"truncate": func(l []string) []string { return l[:4] }, // detected only via sequence expectations; see below
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "a.jsonl")
			fill(t, p, 5)
			b, _ := os.ReadFile(p)
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			os.WriteFile(p, []byte(strings.Join(mutate(lines), "\n")+"\n"), 0o600)
			n, err := Verify(p)
			if name == "truncate" {
				// Truncating the tail leaves a valid shorter chain. Callers that need
				// tail protection must record the head hash elsewhere (documented gap).
				if err != nil || n != 4 {
					t.Fatalf("%d %v", n, err)
				}
				return
			}
			if err == nil {
				t.Fatal("tampering not detected")
			}
		})
	}
}

func TestOpenRefusesCorruptLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, 3)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "policy.update", "policy.delete", 1)), 0o600)
	if _, err := Open(p, nil); err == nil {
		t.Fatal("opened a corrupt log")
	}
}

func TestFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	fill(t, p, 1)
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
