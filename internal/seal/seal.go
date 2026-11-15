// Package seal encrypts the control plane's private files at rest with a key the operator keeps somewhere
// else (GAP-REQ-02). It uses AES-256-GCM. Each file is bound to its own name, so a sealed store cannot be
// swapped for a sealed key file. It protects the data directory, a disk image and a backup if they are
// stolen without the key. It does not protect against someone who is already root on the running
// control plane: the key and the plain data are in its memory.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var magic = []byte("ZTXSEAL1")

// ErrNeedKey means a file is sealed and no key was given.
var ErrNeedKey = errors.New("seal: the file is encrypted; give the master key (-master-key-file or ZTX_MASTER_KEY)")

// ErrWrongKey means the key does not open the file, or the file was changed.
var ErrWrongKey = errors.New("seal: the master key does not open this file, or the file was changed")

// Key is a 256-bit master key.
type Key struct{ b [32]byte }

// Generate makes a new random key and returns it in the text form ParseKey reads.
func Generate() string {
	var k [32]byte
	rand.Read(k[:])
	return base64.RawURLEncoding.EncodeToString(k[:])
}

// ParseKey reads 32 bytes written as 64 hex digits or as base64 (padded or not, standard or URL alphabet).
func ParseKey(s string) (*Key, error) {
	s = strings.TrimSpace(s)
	var raw []byte
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			raw = b
		}
	}
	if raw == nil {
		for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
			if b, err := enc.DecodeString(s); err == nil {
				raw = b
				break
			}
		}
	}
	if len(raw) != 32 {
		return nil, errors.New("seal: the master key must be 32 random bytes written as 64 hex digits or base64 (ztx-cp gen-master-key makes one)")
	}
	k := &Key{}
	copy(k.b[:], raw)
	return k, nil
}

// IsSealed reports whether b is a sealed file.
func IsSealed(b []byte) bool {
	return len(b) >= len(magic) && string(b[:len(magic)]) == string(magic)
}

func (k *Key) aead() cipher.AEAD {
	blk, _ := aes.NewCipher(k.b[:])
	g, _ := cipher.NewGCM(blk)
	return g
}

// Seal encrypts plain; name is bound to the result.
func (k *Key) Seal(name string, plain []byte) []byte {
	g := k.aead()
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	out := append(append([]byte{}, magic...), nonce...)
	return g.Seal(out, nonce, plain, []byte(name))
}

// Open decrypts a sealed file. A nil key gives ErrNeedKey.
func (k *Key) Open(name string, sealed []byte) ([]byte, error) {
	if !IsSealed(sealed) {
		return nil, errors.New("seal: not a sealed file")
	}
	if k == nil {
		return nil, ErrNeedKey
	}
	g := k.aead()
	rest := sealed[len(magic):]
	if len(rest) < g.NonceSize()+g.Overhead() {
		return nil, ErrWrongKey
	}
	p, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], []byte(name))
	if err != nil {
		return nil, ErrWrongKey
	}
	return p, nil
}

// Read returns the content of the file, decrypting it if it is sealed. A plain file is returned as it is.
func Read(path string, k *Key) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if IsSealed(b) {
		return k.Open(filepath.Base(path), b)
	}
	return b, nil
}

// Write stores b at path (mode 0600, written under a temporary name and renamed), sealed when k is not nil.
func Write(path string, b []byte, k *Key) error {
	if k != nil {
		b = k.Seal(filepath.Base(path), b)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// SealInPlace encrypts a plain file with k and reports whether it changed anything. A file that is
// already sealed is left alone, but it is checked to open with this key, so a wrong key is found at
// start-up and not at the first save. A missing file is not an error.
func SealInPlace(path string, k *Key) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if IsSealed(b) {
		if _, err := k.Open(filepath.Base(path), b); err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
		return false, nil
	}
	return true, Write(path, b, k)
}
