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
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/seal"
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
	// RoleWorkspace marks a credential issued to the workspace browser. The role is in the
	// certificate, so a plain agent cannot claim to be a workspace.
	RoleWorkspace = "workspace"
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
	if c.Key == nil {
		return nil, errors.New("pki: this CA is verify-only")
	}
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

// RedeemIf consumes the token only if want accepts its tenant and group. A token offered
// to the wrong kind of endpoint is refused and stays valid for the right one.
func (t *Tokens) RedeemIf(tok string, want func(tenant, group string) bool) (tenant, group string, err error) {
	h := hashToken(tok)
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.byH[h]
	if !ok || t.now().After(rec.Expires) {
		delete(t.byH, h)
		return "", "", ErrBadToken
	}
	if !want(rec.Tenant, rec.Group) {
		return "", "", ErrBadToken
	}
	delete(t.byH, h)
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
	return LoadOrCreateCAKey(dir, name, now, nil)
}

// LoadOrCreateCAKey is LoadOrCreateCA with a master key: the CA key file is read sealed or plain and is
// written sealed when k is not nil.
func LoadOrCreateCAKey(dir, name string, now Clock, k *seal.Key) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kp, cp := filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem")
	kb, err1 := seal.Read(kp, k)
	cb, err2 := os.ReadFile(cp)
	if errors.Is(err1, seal.ErrNeedKey) || errors.Is(err1, seal.ErrWrongKey) {
		return nil, fmt.Errorf("%s: %w", kp, err1)
	}
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
	if err := seal.Write(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), k); err != nil {
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

// VerifierFromPEM builds a verify-only CA (no signing key) from a CA
// certificate. Enforcement nodes use it: they never hold the CA key.
func VerifierFromPEM(pemBytes []byte, now Clock) (*CA, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("pki: no certificate in PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, now: now, pool: pool}, nil
}

// LoadOrCreateSigner keeps the policy-signing key in dir (policy.key, mode 0600).
// Enforcement nodes pin the matching public key at enrolment.
func LoadOrCreateSigner(dir string) (*ecdsa.PrivateKey, error) {
	return LoadOrCreateSignerKey(dir, nil)
}

// LoadOrCreateSignerKey is LoadOrCreateSigner with a master key, as LoadOrCreateCAKey.
func LoadOrCreateSignerKey(dir string, k *seal.Key) (*ecdsa.PrivateKey, error) {
	p := filepath.Join(dir, "policy.key")
	b, err := seal.Read(p, k)
	if errors.Is(err, seal.ErrNeedKey) || errors.Is(err, seal.ErrWrongKey) {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("pki: policy.key is unreadable")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(priv)
	return priv, seal.Write(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), k)
}

// PublicPEM encodes an ECDSA public key for distribution.
func PublicPEM(k *ecdsa.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// ParsePublicPEM decodes a key written by PublicPEM.
func ParsePublicPEM(b []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("pki: no public key in PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("pki: not an ECDSA key")
	}
	return pk, nil
}

// CAFromPEM rebuilds a signing CA from its certificate and key (used for per-tenant intercept CAs).
func CAFromPEM(certPEM, keyPEM []byte, now Clock) (*CA, error) {
	cblk, _ := pem.Decode(certPEM)
	kblk, _ := pem.Decode(keyPEM)
	if cblk == nil || kblk == nil {
		return nil, errors.New("pki: unreadable CA PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
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

// KeyPEM returns the CA private key (the intercept CA key must reach enforcement nodes).
func (c *CA) KeyPEM() []byte {
	der, _ := x509.MarshalECPrivateKey(c.Key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// SignServer issues a TLS server certificate for host (a DNS name or an IP).
func (c *CA) SignServer(pub crypto.PublicKey, host string, ttl time.Duration) ([]byte, error) {
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"smb-ztx inspection"}},
		NotBefore:    c.now().Add(-Tolerance),
		NotAfter:     c.now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	return x509.CreateCertificate(rand.Reader, tpl, c.Cert, pub, c.Key)
}
