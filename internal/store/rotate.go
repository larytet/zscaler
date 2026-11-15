package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/larytet/zscaler/internal/pki"
)

// RotateAdmin replaces an administrator's token with a new one, shown once; the old token stops working
// at once. Role, expiry, note and support mark are kept (GAP-REQ-05).
func (s *Store) RotateAdmin(tenant, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldKey string
	var rec adminRec
	for k, a := range s.d.Admins {
		if a.Tenant == tenant && a.Name == name {
			oldKey, rec = k, a
		}
	}
	if oldKey == "" {
		return "", ErrNotFound
	}
	if !rec.Expires.IsZero() && !rec.Expires.After(s.now()) {
		return "", errors.New("the account has expired; make a new one")
	}
	tok := newToken()
	delete(s.d.Admins, oldKey)
	rec.Rotated, rec.LastUsed = s.now().UTC(), s.now().UTC()
	s.d.Admins[hash(tok)] = rec
	return tok, s.save()
}

// Fingerprint is the SHA-256 of a PEM certificate's DER form, in hex ("" if it is not a certificate).
func Fingerprint(certPEM string) string {
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return ""
	}
	h := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(h[:])
}

// RotateInspection replaces the tenant's TLS inspection CA and the leaf key its certificates are made
// with. Everything the old CA signed stops being trusted once devices have the new certificate, and
// devices that still trust only the old one see certificate errors on inspected sites until they do. It
// returns the fingerprints of the old and the new CA certificate.
func (s *Store) RotateInspection(tenant string) (oldFP, newFP string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.tenant(tenant)
	if err != nil {
		return "", "", err
	}
	if t.Inspect.CAKey == "" {
		return "", "", fmt.Errorf("inspection has never been turned on, so there is no CA to replace: %w", ErrNotFound)
	}
	ca, err := pki.NewCA(tenant+" TLS inspection CA", nil)
	if err != nil {
		return "", "", err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	oldFP = Fingerprint(t.Inspect.CACert)
	t.Inspect.CACert, t.Inspect.CAKey = string(ca.PEM()), string(ca.KeyPEM())
	t.Inspect.LeafKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	t.Inspect.Rotated = s.now().UTC()
	return oldFP, Fingerprint(t.Inspect.CACert), s.save()
}
