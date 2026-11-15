// Package release builds the programs that are shipped (NFR-024): deterministically, so that anyone with
// the source gets the same bytes; with a checksum file; with a software bill of materials (CycloneDX)
// read from the binaries themselves; and with an ed25519 signature over the checksums. Verify checks
// all of it, and notices a file that was changed, removed or added.
//
// What it does not do: hold a signing key for you (keep it in your build system's secret store or an
// HSM and give it to the build), notarise macOS binaries or sign Windows installers (those need the
// platform vendors' certificates), or build installers.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Target is one program for one platform.
type Target struct{ Cmd, GOOS, GOARCH string }

// File is the name of the built file.
func (t Target) File() string {
	n := fmt.Sprintf("%s_%s_%s", t.Cmd, t.GOOS, t.GOARCH)
	if t.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// Targets is what a release contains: the endpoint agent for the common desktop platforms, the
// connector for Linux, and the enforcement node and control plane for Linux.
var Targets = []Target{
	{"ztx-agent", "linux", "amd64"}, {"ztx-agent", "linux", "arm64"},
	{"ztx-agent", "darwin", "amd64"}, {"ztx-agent", "darwin", "arm64"},
	{"ztx-agent", "windows", "amd64"},
	{"ztx-connector", "linux", "amd64"}, {"ztx-connector", "linux", "arm64"},
	{"ztx-en", "linux", "amd64"}, {"ztx-cp", "linux", "amd64"},
}

// Options for Build.
type Options struct {
	Root    string // the source tree (where go.mod is)
	Out     string // where the files go
	Version string
	Targets []Target
	Go      string   // the go command, default "go"
	Env     []string // extra environment, for example a separate GOCACHE
}

const modulePath = "github.com/larytet/zscaler"

// Build compiles every target into Out and returns the file names. The flags are the point: -trimpath
// removes the build directory from the binary, -buildvcs=false the state of the checkout, the empty build
// id and stripped symbols the rest of what varies, CGO is off so no C toolchain leaks in, and the version
// is stamped into the programs that report one.
func Build(o Options) ([]string, error) {
	if o.Go == "" {
		o.Go = "go"
	}
	if o.Version == "" || strings.ContainsAny(o.Version, " \t\r\n'\"\\") {
		return nil, errors.New("release: a version without spaces or quotes is required")
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	ld := fmt.Sprintf("-s -w -buildid= -X main.version=%s -X %s/internal/agent.Version=%s", o.Version, modulePath, o.Version)
	var files []string
	for _, t := range o.Targets {
		out := filepath.Join(o.Out, t.File())
		cmd := exec.Command(o.Go, "build", "-trimpath", "-buildvcs=false", "-ldflags", ld, "-o", out, "./cmd/"+t.Cmd)
		cmd.Dir = o.Root
		cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0", "GOOS="+t.GOOS, "GOARCH="+t.GOARCH, "GOFLAGS="), o.Env...)
		if b, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("release: building %s: %v\n%s", t.File(), err, b)
		}
		files = append(files, t.File())
	}
	sort.Strings(files)
	return files, nil
}

func hashFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// the files in a release directory that the checksums cover: everything except the checksums and their signature
func covered(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if e.IsDir() || e.Name() == "SHA256SUMS" || e.Name() == "SHA256SUMS.sig" {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// Sums returns the checksum file for a directory ("hash  name" per line, sorted, as sha256sum -c reads it).
func Sums(dir string) (string, error) {
	names, err := covered(dir)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, n := range names {
		h, err := hashFile(filepath.Join(dir, n))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "%s  %s\n", h, n)
	}
	return sb.String(), nil
}

// SBOMName is the name of the bill of materials in a release directory.
const SBOMName = "sbom.cdx.json"

type bomHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type bomProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type bomComp struct {
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Version    string    `json:"version,omitempty"`
	Purl       string    `json:"purl,omitempty"`
	Hashes     []bomHash `json:"hashes,omitempty"`
	Properties []bomProp `json:"properties,omitempty"`
}

// SBOM writes a CycloneDX 1.5 bill of materials for the given binaries in dir, read from the build
// information inside them: the Go version they were built with and every module they contain. It has no
// timestamp and a serial number derived from its content, so building it again gives the same file.
func SBOM(dir string, files []string, version string) ([]byte, error) {
	var comps []bomComp
	seen := map[string]bool{}
	sort.Strings(files)
	for _, f := range files {
		p := filepath.Join(dir, f)
		bi, err := buildinfo.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("release: %s has no Go build information: %w", f, err)
		}
		h, err := hashFile(p)
		if err != nil {
			return nil, err
		}
		props := []bomProp{{"go:version", bi.GoVersion}, {"go:module", bi.Main.Path}}
		for _, s := range bi.Settings {
			switch s.Key {
			case "CGO_ENABLED", "GOOS", "GOARCH", "-trimpath":
				props = append(props, bomProp{"go:" + s.Key, s.Value})
			}
		}
		comps = append(comps, bomComp{Type: "application", Name: f, Version: version, Hashes: []bomHash{{"SHA-256", h}}, Properties: props})
		if k := "go-stdlib@" + bi.GoVersion; !seen[k] {
			seen[k] = true
			comps = append(comps, bomComp{Type: "library", Name: "go-standard-library", Version: bi.GoVersion, Purl: "pkg:golang/std@" + strings.TrimPrefix(bi.GoVersion, "go")})
		}
		for _, d := range bi.Deps {
			if k := d.Path + "@" + d.Version; !seen[k] {
				seen[k] = true
				c := bomComp{Type: "library", Name: d.Path, Version: d.Version, Purl: "pkg:golang/" + d.Path + "@" + d.Version}
				if d.Sum != "" {
					c.Hashes = []bomHash{{"SHA-256", strings.TrimPrefix(d.Sum, "h1:")}}
				}
				comps = append(comps, c)
			}
		}
	}
	body := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata":   map[string]any{"component": bomComp{Type: "application", Name: "smb-ztx", Version: version}, "tools": []map[string]string{{"name": "ztx-release"}}},
		"components": comps}
	pre, _ := json.Marshal(body)
	sum := sha256.Sum256(pre)
	u := hex.EncodeToString(sum[:16])
	body["serialNumber"] = "urn:uuid:" + u[:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:]
	return json.MarshalIndent(body, "", "  ")
}

// Keygen makes an ed25519 key pair as PEM (PKCS #8 private, PKIX public).
func Keygen() (pub, priv []byte, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pb, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	sb, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sb}), nil
}

func parsePriv(p []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("release: not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("release: the key is not an ed25519 key")
	}
	return sk, nil
}

func parsePub(p []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("release: not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("release: the key is not an ed25519 key")
	}
	return pk, nil
}

// Finish writes the bill of materials, the checksums and, when a private key is given, the signature
// over the checksums, into dir.
func Finish(dir string, files []string, version string, privPEM []byte) error {
	sbom, err := SBOM(dir, files, version)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, SBOMName), sbom, 0o644); err != nil {
		return err
	}
	sums, err := Sums(dir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		return err
	}
	if privPEM == nil {
		return nil
	}
	sk, err := parsePriv(privPEM)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(sk, []byte(sums))
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}

// Verify checks a release directory against a public key. It returns every problem found, so a person
// can see all of them at once: a bad or missing signature, a changed, missing or extra file, and a
// bill of materials that does not describe the binaries beside it.
func Verify(dir string, pubPEM []byte) []string {
	var problems []string
	pk, err := parsePub(pubPEM)
	if err != nil {
		return []string{err.Error()}
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return []string{"there is no SHA256SUMS file"}
	}
	sigB, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		problems = append(problems, "there is no signature (SHA256SUMS.sig)")
	} else if sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB))); err != nil || !ed25519.Verify(pk, sums, sig) {
		problems = append(problems, "the signature does not match the checksums and this key")
	}
	want, err := Sums(dir)
	if err != nil {
		return append(problems, err.Error())
	}
	if want != string(sums) {
		have := map[string]string{}
		for _, l := range strings.Split(string(sums), "\n") {
			if f := strings.SplitN(l, "  ", 2); len(f) == 2 {
				have[f[1]] = f[0]
			}
		}
		now := map[string]string{}
		for _, l := range strings.Split(want, "\n") {
			if f := strings.SplitN(l, "  ", 2); len(f) == 2 {
				now[f[1]] = f[0]
			}
		}
		for n, h := range have {
			switch {
			case now[n] == "":
				problems = append(problems, "missing: "+n)
			case now[n] != h:
				problems = append(problems, "changed: "+n)
			}
		}
		for n := range now {
			if have[n] == "" {
				problems = append(problems, "not in the checksums: "+n)
			}
		}
	}
	// the bill of materials must describe these binaries
	raw, err := os.ReadFile(filepath.Join(dir, SBOMName))
	if err != nil {
		return append(problems, "there is no "+SBOMName)
	}
	var bom struct {
		Components []bomComp `json:"components"`
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		return append(problems, SBOMName+" is not valid JSON")
	}
	described := map[string]bool{}
	for _, c := range bom.Components {
		if c.Type != "application" {
			continue
		}
		described[c.Name] = true
		h, err := hashFile(filepath.Join(dir, c.Name))
		switch {
		case err != nil:
			problems = append(problems, SBOMName+" describes "+c.Name+", which is not here")
		case len(c.Hashes) == 0 || c.Hashes[0].Content != h:
			problems = append(problems, SBOMName+" has another hash for "+c.Name)
		}
	}
	names, _ := covered(dir)
	for _, n := range names {
		if n != SBOMName && !described[n] {
			problems = append(problems, SBOMName+" does not describe "+n)
		}
	}
	sort.Strings(problems)
	return problems
}

// Same reports whether two directories hold byte-identical files with the same names, for the
// reproducibility check.
func Same(a, b string) (bool, error) {
	na, err := covered(a)
	if err != nil {
		return false, err
	}
	nb, err := covered(b)
	if err != nil {
		return false, err
	}
	if len(na) != len(nb) {
		return false, nil
	}
	for i := range na {
		if na[i] != nb[i] {
			return false, nil
		}
		x, _ := os.ReadFile(filepath.Join(a, na[i]))
		y, _ := os.ReadFile(filepath.Join(b, nb[i]))
		if !bytes.Equal(x, y) {
			return false, nil
		}
	}
	return true, nil
}
