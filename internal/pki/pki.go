// Package pki issues short-lived client certificates, tracks revocation and
// handles one-time enrolment tokens (DESIGN.md D4.2, D4.4, D5.5).
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	Tolerance = 2 * time.Minute
	DeviceTTL = 12 * time.Hour
)

// Role is encoded in the certificate's organizational unit.
const (
	RoleDevice    = "device"
	RoleConnector = "connector"
	RoleEN        = "en"
)

type Clock func() time.Time

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	now  Clock
	pool *x509.CertPool
}

func NewCA(name string, now Clock) (*CA, error) {
	if now == nil {
		now = time.Now
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"smb-ztx"}},
		NotBefore:             now().Add(-Tolerance),
		NotAfter:              now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, now: now, pool: pool}, nil
}

func (c *CA) Pool() *x509.CertPool { return c.pool }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n.Add(n, big.NewInt(1))
}

// Identity is what a certificate says about its holder.
type Identity struct {
	Tenant, Subject, Device, Role string
	Serial                        string
	NotAfter                      time.Time
}

// Sign issues a client-auth certificate for pub. The subject is
// "tenant/subject/device"; usage is client auth, plus server auth for ENs.
func (c *CA) Sign(pub crypto.PublicKey, id Identity, ttl time.Duration, dnsNames ...string) ([]byte, error) {
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if id.Role == RoleEN {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:         id.Tenant + "/" + id.Subject + "/" + id.Device,
			Organization:       []string{id.Tenant},
			OrganizationalUnit: []string{id.Role},
		},
		NotBefore:   c.now().Add(-Tolerance),
		NotAfter:    c.now().Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: eku,
	}
	for _, n := range dnsNames {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	return x509.CreateCertificate(rand.Reader, tpl, c.Cert, pub, c.Key)
}

var ErrRevoked = errors.New("pki: certificate revoked")

// Verify checks the chain, usage and revocation. An expired certificate is
// accepted for up to Tolerance (clock skew), matching the issue backdating.
func (c *CA) Verify(cert *x509.Certificate, revoked *Revocations) (Identity, error) {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.pool,
		CurrentTime: c.now().Add(-Tolerance + time.Second),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return Identity{}, err
	}
	if c.now().After(cert.NotAfter.Add(Tolerance)) {
		return Identity{}, errors.New("pki: certificate expired")
	}
	if revoked != nil && revoked.IsRevoked(cert.SerialNumber.String()) {
		return Identity{}, ErrRevoked
	}
	return ParseIdentity(cert)
}

func ParseIdentity(cert *x509.Certificate) (Identity, error) {
	parts := splitN(cert.Subject.CommonName, '/', 3)
	if len(parts) != 3 || len(cert.Subject.OrganizationalUnit) != 1 {
		return Identity{}, errors.New("pki: malformed subject")
	}
	return Identity{Tenant: parts[0], Subject: parts[1], Device: parts[2],
		Role: cert.Subject.OrganizationalUnit[0], Serial: cert.SerialNumber.String(), NotAfter: cert.NotAfter}, nil
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Revocations is a set of revoked serials, pruned after the cert would have
// expired anyway.
type Revocations struct {
	mu  sync.RWMutex
	set map[string]time.Time
	now Clock
}

func NewRevocations(now Clock) *Revocations {
	if now == nil {
		now = time.Now
	}
	return &Revocations{set: map[string]time.Time{}, now: now}
}

func (r *Revocations) Revoke(serial string, expires time.Time) {
	r.mu.Lock()
	r.set[serial] = expires
	r.mu.Unlock()
}

func (r *Revocations) IsRevoked(serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.set[serial]
	return ok
}

// Prune drops entries whose certificates have expired. Returns how many.
func (r *Revocations) Prune() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for s, exp := range r.set {
		if r.now().After(exp.Add(Tolerance)) {
			delete(r.set, s)
			n++
		}
	}
	return n
}

func (r *Revocations) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.set)
}

// Tokens issues single-use enrolment tokens and stores only their hash.
type Tokens struct {
	mu   sync.Mutex
	byH  map[string]tokenRec
	now  Clock
	life time.Duration
}

type tokenRec struct {
	Tenant, Group string
	Expires       time.Time
}

func NewTokens(now Clock, life time.Duration) *Tokens {
	if now == nil {
		now = time.Now
	}
	if life == 0 {
		life = time.Hour
	}
	return &Tokens{byH: map[string]tokenRec{}, now: now, life: life}
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Issue returns the plaintext token. It is never stored.
func (t *Tokens) Issue(tenant, group string) string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	t.mu.Lock()
	t.byH[hashToken(tok)] = tokenRec{tenant, group, t.now().Add(t.life)}
	t.mu.Unlock()
	return tok
}

var ErrBadToken = errors.New("pki: invalid, used or expired token")

// Redeem consumes the token. Second use and expired tokens fail.
func (t *Tokens) Redeem(tok string) (tenant, group string, err error) {
	h := hashToken(tok)
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byH[h]
	if !ok {
		return "", "", ErrBadToken
	}
	delete(t.byH, h)
	if t.now().After(rec.Expires) {
		return "", "", ErrBadToken
	}
	return rec.Tenant, rec.Group, nil
}

// Stored returns what is held at rest, for tests that check nothing leaks.
func (t *Tokens) Stored() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for k := range t.byH {
		out = append(out, k)
	}
	return out
}

// LoadOrCreateCA keeps the CA key and certificate in dir (ca.key, ca.pem, mode 0600).
func LoadOrCreateCA(dir, name string, now Clock) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kp, cp := filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem")
	kb, err1 := os.ReadFile(kp)
	cb, err2 := os.ReadFile(cp)
	if err1 == nil && err2 == nil {
		kblk, _ := pem.Decode(kb)
		cblk, _ := pem.Decode(cb)
		if kblk == nil || cblk == nil {
			return nil, errors.New("pki: ca files are unreadable")
		}
		key, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, err
		}
		if now == nil {
			now = time.Now
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return &CA{Cert: cert, Key: key, now: now, pool: pool}, nil
	}
	ca, err := NewCA(name, now)
	if err != nil {
		return nil, err
	}
	kder, _ := x509.MarshalECPrivateKey(ca.Key)
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600); err != nil {
		return nil, err
	}
	return ca, nil
}

// PEM returns the CA certificate for distribution to endpoints.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}
