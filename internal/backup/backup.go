// Package backup copies the control plane's data directory into one file and brings it back (GAP-REQ-01).
// The file is a gzip-compressed tar with a manifest of SHA-256 sums as its last entry, so a damaged or
// altered file is refused before anything is written. It contains the CA private keys, the policy signing
// key and every tenant secret in clear: keep it as carefully as the keys themselves.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/store"
)

const (
	manifestName = "MANIFEST.json"
	format       = 1
	maxFile      = 1 << 30 // one file; far above any small business's day of records
	maxFiles     = 200000
)

// required files: without them it is not a control plane backup, and a restore would not give back the
// same certificates and state.
var required = []string{"store.json", "ca.key", "ca.pem", "policy.key"}

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format  int       `json:"format"`
	Created time.Time `json:"created"`
	Version string    `json:"version"`
	Files   []Entry   `json:"files"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Create writes the backup of dataDir to out (mode 0600, written under a temporary name and renamed, so a
// failed run leaves no half file). It can run while the control plane is up: store.json is replaced
// atomically by the store, and the append-only logs are cut at their last complete line.
func Create(dataDir, out string, now time.Time, version string) (Manifest, error) {
	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return Manifest{}, err
	}
	absOut, err := filepath.Abs(out)
	if err != nil {
		return Manifest{}, err
	}
	if strings.HasPrefix(absOut, absData+string(filepath.Separator)) {
		return Manifest{}, errors.New("backup: the output file must not be inside the data directory")
	}
	var names []string
	err = filepath.WalkDir(absData, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && !strings.HasSuffix(p, ".tmp") {
			rel, _ := filepath.Rel(absData, p)
			names = append(names, filepath.ToSlash(rel))
		} else if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("backup: %s is not a regular file (links and devices are not copied)", p)
		}
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Strings(names)
	for _, r := range required {
		if _, e := os.Stat(filepath.Join(absData, r)); e != nil {
			return Manifest{}, fmt.Errorf("backup: %s is not a control plane data directory (missing %s)", dataDir, r)
		}
	}
	if len(names) > maxFiles {
		return Manifest{}, errors.New("backup: too many files")
	}
	tmp := absOut + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return Manifest{}, err
	}
	fail := func(e error) (Manifest, error) { f.Close(); os.Remove(tmp); return Manifest{}, e }
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	m := Manifest{Format: format, Created: now.UTC(), Version: version}
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(absData, filepath.FromSlash(n)))
		if err != nil {
			return fail(err)
		}
		if strings.HasSuffix(n, ".jsonl") { // a line being written right now must not end up half in the copy
			if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
				b = b[:i+1]
			} else {
				b = nil
			}
		}
		if len(b) > maxFile {
			return fail(fmt.Errorf("backup: %s is too large", n))
		}
		if err := put(n, b); err != nil {
			return fail(err)
		}
		m.Files = append(m.Files, Entry{Path: n, Size: int64(len(b)), SHA256: sum(b)})
	}
	mb, _ := json.MarshalIndent(m, "", " ")
	if err := put(manifestName, mb); err != nil {
		return fail(err)
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return Manifest{}, err
	}
	return m, os.Rename(tmp, absOut)
}

// safeName accepts only plain relative names that stay inside the directory.
func safeName(n string) bool {
	if n == "" || strings.Contains(n, "\\") || strings.ContainsRune(n, 0) || path.IsAbs(n) {
		return false
	}
	return path.Clean(n) == n && n != "." && n != ".." && !strings.HasPrefix(n, "../")
}

// walk reads the file once, checks every entry, and calls each with the content (when each is not nil).
// It returns the manifest after checking it against what was read.
func walk(in string, each func(name string, b []byte) error) (Manifest, error) {
	f, err := os.Open(in)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return Manifest{}, errors.New("backup: not a backup file (not gzip)")
	}
	tr := tar.NewReader(gz)
	got := map[string]Entry{}
	var man *Manifest
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("backup: the file is damaged: %w", err)
		}
		if count++; count > maxFiles+1 {
			return Manifest{}, errors.New("backup: too many entries")
		}
		if h.Typeflag != tar.TypeReg || !safeName(h.Name) {
			return Manifest{}, fmt.Errorf("backup: refused entry %q (only plain files with plain names are accepted)", h.Name)
		}
		if man != nil {
			return Manifest{}, errors.New("backup: entries after the manifest")
		}
		if h.Size < 0 || h.Size > maxFile {
			return Manifest{}, fmt.Errorf("backup: entry %q has an unreasonable size", h.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return Manifest{}, fmt.Errorf("backup: the file is damaged at %q", h.Name)
		}
		if h.Name == manifestName {
			var m Manifest
			if err := json.Unmarshal(b, &m); err != nil {
				return Manifest{}, errors.New("backup: the manifest is not valid")
			}
			man = &m
			continue
		}
		if _, dup := got[h.Name]; dup {
			return Manifest{}, fmt.Errorf("backup: %q appears twice", h.Name)
		}
		got[h.Name] = Entry{Path: h.Name, Size: h.Size, SHA256: sum(b)}
		if each != nil {
			if err := each(h.Name, b); err != nil {
				return Manifest{}, err
			}
		}
	}
	if man == nil {
		return Manifest{}, errors.New("backup: no manifest (the file is incomplete)")
	}
	if man.Format != format {
		return Manifest{}, fmt.Errorf("backup: format %d is not supported", man.Format)
	}
	if len(man.Files) != len(got) {
		return Manifest{}, errors.New("backup: the manifest does not match the files")
	}
	for _, e := range man.Files {
		g, ok := got[e.Path]
		if !ok || g.SHA256 != e.SHA256 || g.Size != e.Size {
			return Manifest{}, fmt.Errorf("backup: %q does not match its checksum (the file was changed or damaged)", e.Path)
		}
	}
	for _, r := range required {
		if _, ok := got[r]; !ok {
			return Manifest{}, fmt.Errorf("backup: not a control plane backup (missing %s)", r)
		}
	}
	return *man, nil
}

// Verify checks a backup file without writing anything.
func Verify(in string) (Manifest, error) { return walk(in, nil) }

// Restore checks the file, then puts its content into dataDir. A directory that already holds data is
// refused unless force is set; with force it is moved aside to <dir>.before-restore-<time>, never
// overwritten, and the new one is built next to it and renamed into place, so a failure in the middle
// leaves the old data where it was. The restored store and audit chain are checked before it returns.
// Stop the control plane first.
func Restore(in, dataDir string, force bool, now time.Time) (Manifest, string, error) {
	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return Manifest{}, "", err
	}
	if _, err := Verify(in); err != nil { // nothing is written until the whole file has checked out
		return Manifest{}, "", err
	}
	existing := false
	if ents, err := os.ReadDir(absData); err == nil && len(ents) > 0 {
		existing = true
		if !force {
			return Manifest{}, "", fmt.Errorf("backup: %s already holds data; stop the control plane and use -force to move it aside and restore", dataDir)
		}
	}
	stage := fmt.Sprintf("%s.restore-%d", absData, now.UnixNano())
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return Manifest{}, "", err
	}
	cleanup := func() { os.RemoveAll(stage) }
	man, err := walk(in, func(name string, b []byte) error {
		p := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o600)
	})
	if err != nil {
		cleanup()
		return Manifest{}, "", err
	}
	if _, err := store.Open(filepath.Join(stage, "store.json")); err != nil {
		cleanup()
		return Manifest{}, "", fmt.Errorf("backup: the restored store does not load: %w", err)
	}
	if ap := filepath.Join(stage, "audit.jsonl"); fileExists(ap) {
		if _, err := audit.Verify(ap); err != nil {
			cleanup()
			return Manifest{}, "", fmt.Errorf("backup: the restored audit log fails its check: %w", err)
		}
	}
	moved := ""
	if existing {
		moved = fmt.Sprintf("%s.before-restore-%s", absData, now.UTC().Format("20060102-150405"))
		if err := os.Rename(absData, moved); err != nil {
			cleanup()
			return Manifest{}, "", err
		}
	} else if err := os.Remove(absData); err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanup()
		return Manifest{}, "", err
	}
	if err := os.Rename(stage, absData); err != nil {
		cleanup()
		return Manifest{}, moved, err
	}
	return man, moved, nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
