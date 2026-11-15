package release

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal("cannot find the source tree")
	}
	return root
}

// copyTree copies the source to another directory, so a build there has another absolute path.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() && (rel == ".git" || rel == ".doc" || rel == "bin" || rel == "dist" || rel == "docs") {
			return fs.SkipDir
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(filepath.Join(to, rel))
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

var testTargets = []Target{{"ztx-agent", "linux", "amd64"}, {"ztx-connector", "windows", "amd64"}}

func TestBuildsAreReproducibleAndStampedAndSignedEndToEnd(t *testing.T) { // AGT-035 (NFR-024)
	if testing.Short() {
		t.Skip("builds the programs several times")
	}
	root := repoRoot(t)
	d1, d2, d3 := t.TempDir(), t.TempDir(), t.TempDir()
	// the same source in another place, with another build cache: the bytes must be the same
	other := filepath.Join(t.TempDir(), "a", "different", "path", "src")
	copyTree(t, root, other)
	files, err := Build(Options{Root: root, Out: d1, Version: "v9.9.9", Targets: testTargets})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Root: other, Out: d2, Version: "v9.9.9", Targets: testTargets, Env: []string{"GOCACHE=" + t.TempDir()}}); err != nil {
		t.Fatal(err)
	}
	same, err := Same(d1, d2)
	if err != nil || !same {
		t.Fatalf("the same source, built in another directory with a clean cache, gave other bytes (%v)", err)
	}
	// another version gives another binary: the stamp is in it
	if _, err := Build(Options{Root: root, Out: d3, Version: "v9.9.8", Targets: testTargets}); err != nil {
		t.Fatal(err)
	}
	if same, _ := Same(d1, d3); same {
		t.Fatal("the version is not in the binaries")
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		out, err := exec.Command(filepath.Join(d1, "ztx-agent_linux_amd64"), "-version").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "ztx-agent v9.9.9" {
			t.Fatalf("%v %q", err, out)
		}
	}
	// finish both and compare the checksum files and the bill of materials too: they are reproducible as well
	pub, priv, err := Keygen()
	if err != nil {
		t.Fatal(err)
	}
	if err := Finish(d1, files, "v9.9.9", priv); err != nil {
		t.Fatal(err)
	}
	if err := Finish(d2, files, "v9.9.9", priv); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"SHA256SUMS", SBOMName} {
		a, _ := os.ReadFile(filepath.Join(d1, f))
		b, _ := os.ReadFile(filepath.Join(d2, f))
		if string(a) != string(b) || len(a) == 0 {
			t.Fatalf("%s differs between two builds of the same source", f)
		}
	}
	if problems := Verify(d1, pub); len(problems) != 0 {
		t.Fatalf("a fresh release must verify: %v", problems)
	}
	// the SBOM names what the binaries are
	sb, _ := os.ReadFile(filepath.Join(d1, SBOMName))
	for _, want := range []string{`"bomFormat": "CycloneDX"`, `"specVersion": "1.5"`, "ztx-agent_linux_amd64", "ztx-connector_windows_amd64.exe", "go-standard-library", `"go:CGO_ENABLED"`, "github.com/larytet/zscaler"} {
		if !strings.Contains(string(sb), want) {
			t.Errorf("the bill of materials lacks %q", want)
		}
	}
	if strings.Contains(string(sb), "timestamp") {
		t.Error("a timestamp would make the bill of materials differ between builds")
	}
}

// a release directory made of copies of this test's own binary, which carries Go build information
func fakeRelease(t *testing.T) (dir string, pub []byte) {
	t.Helper()
	dir = t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, n := range []string{"ztx-a_linux_amd64", "ztx-b_linux_amd64"} {
		if err := os.WriteFile(filepath.Join(dir, n), append(b, []byte(n)...), 0o755); err != nil { // the copies differ
			t.Fatal(err)
		}
		files = append(files, n)
	}
	pub, priv, _ := Keygen()
	if err := Finish(dir, files, "v1.0.0", priv); err != nil {
		t.Fatal(err)
	}
	return dir, pub
}

func TestVerifyFindsEveryKindOfTampering(t *testing.T) { // AGT-035 (NFR-024)
	dir, pub := fakeRelease(t)
	if p := Verify(dir, pub); len(p) != 0 {
		t.Fatalf("%v", p)
	}
	contains := func(problems []string, sub string) bool {
		for _, p := range problems {
			if strings.Contains(p, sub) {
				return true
			}
		}
		return false
	}
	restore := func(name string) func() {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return func() { os.WriteFile(filepath.Join(dir, name), b, 0o755) }
	}
	// a changed binary: the checksum and the bill of materials both notice
	undo := restore("ztx-a_linux_amd64")
	f, _ := os.OpenFile(filepath.Join(dir, "ztx-a_linux_amd64"), os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("tampered"))
	f.Close()
	if p := Verify(dir, pub); !contains(p, "changed: ztx-a_linux_amd64") || !contains(p, "another hash for ztx-a_linux_amd64") {
		t.Fatalf("%v", p)
	}
	undo()
	// a removed binary
	undo = restore("ztx-b_linux_amd64")
	os.Remove(filepath.Join(dir, "ztx-b_linux_amd64"))
	if p := Verify(dir, pub); !contains(p, "missing: ztx-b_linux_amd64") {
		t.Fatalf("%v", p)
	}
	undo()
	// an added file
	os.WriteFile(filepath.Join(dir, "extra.exe"), []byte("MZ"), 0o755)
	if p := Verify(dir, pub); !contains(p, "not in the checksums: extra.exe") || !contains(p, "does not describe extra.exe") {
		t.Fatalf("%v", p)
	}
	os.Remove(filepath.Join(dir, "extra.exe"))
	// the checksums edited to match a changed file: the signature no longer matches
	undo = restore("SHA256SUMS")
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Replace(string(mustRead(t, filepath.Join(dir, "SHA256SUMS"))), "a", "b", 1)), 0o644)
	if p := Verify(dir, pub); !contains(p, "signature does not match") {
		t.Fatalf("%v", p)
	}
	undo()
	// the wrong key, no signature, no bill of materials, a bill that was edited, a bad key
	otherPub, _, _ := Keygen()
	if p := Verify(dir, otherPub); !contains(p, "signature does not match") {
		t.Fatalf("%v", p)
	}
	undo = restore("SHA256SUMS.sig")
	os.Remove(filepath.Join(dir, "SHA256SUMS.sig"))
	if p := Verify(dir, pub); !contains(p, "no signature") {
		t.Fatalf("%v", p)
	}
	undo()
	undo = restore(SBOMName)
	os.Remove(filepath.Join(dir, SBOMName))
	if p := Verify(dir, pub); len(p) == 0 {
		t.Fatal("a release without a bill of materials must not verify")
	}
	undo()
	if p := Verify(dir, []byte("not a key")); len(p) == 0 {
		t.Fatal("a bad key must not verify anything")
	}
	if p := Verify(t.TempDir(), pub); len(p) == 0 {
		t.Fatal("an empty directory must not verify")
	}
	if p := Verify(dir, pub); len(p) != 0 {
		t.Fatalf("after undoing every change the release verifies again: %v", p)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSBOMNeedsGoBinariesAndIsDeterministic(t *testing.T) { // AGT-035
	dir, _ := fakeRelease(t)
	a, err := SBOM(dir, []string{"ztx-a_linux_amd64", "ztx-b_linux_amd64"}, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SBOM(dir, []string{"ztx-b_linux_amd64", "ztx-a_linux_amd64"}, "v1.0.0") // the order given does not matter
	if string(a) != string(b) {
		t.Fatal("the bill of materials depends on the order of the files")
	}
	os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("not a program"), 0o644)
	if _, err := SBOM(dir, []string{"plain.txt"}, "v1"); err == nil || !strings.Contains(err.Error(), "no Go build information") {
		t.Fatalf("a file that is not a Go binary must be refused: %v", err)
	}
	if _, err := SBOM(dir, []string{"missing"}, "v1"); err == nil {
		t.Fatal("a missing file must be refused")
	}
}

func TestBuildRefusesBadInput(t *testing.T) { // AGT-035
	for _, v := range []string{"", "v1 0", "v1\n", "v'1"} {
		if _, err := Build(Options{Root: t.TempDir(), Out: t.TempDir(), Version: v, Targets: testTargets}); err == nil {
			t.Errorf("version %q was accepted", v)
		}
	}
	if _, err := Build(Options{Root: repoRoot(t), Out: t.TempDir(), Version: "v1", Targets: []Target{{"ztx-nonesuch", "linux", "amd64"}}}); err == nil {
		t.Error("a program that does not exist must be an error")
	}
	if _, err := Build(Options{Root: repoRoot(t), Out: t.TempDir(), Version: "v1", Targets: []Target{{"ztx-agent", "plan9", "nope"}}}); err == nil {
		t.Error("a platform that does not exist must be an error")
	}
	if (Target{"ztx-agent", "windows", "amd64"}).File() != "ztx-agent_windows_amd64.exe" || (Target{"ztx-en", "linux", "amd64"}).File() != "ztx-en_linux_amd64" {
		t.Error("file names")
	}
	pub, priv, err := Keygen()
	if err != nil || len(pub) == 0 || len(priv) == 0 {
		t.Fatal(err)
	}
	if _, err := parsePriv(pub); err == nil {
		t.Error("a public key is not a private key")
	}
	if _, err := parsePub(priv); err == nil {
		t.Error("a private key is not a public key")
	}
}
