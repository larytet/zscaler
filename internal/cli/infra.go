// Package cli has helpers shared by the command-line binaries.
package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/clockhint"
	"github.com/larytet/zscaler/internal/pki"
)

// Secret reads a secret from a file (preferred) or an environment variable.
// Secrets are never taken from command-line arguments, where they would show
// up in process listings.
func Secret(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	return "", nil
}

// Identity is an infrastructure component's key, certificate and trust root.
type Identity struct {
	Cert tls.Certificate
	Leaf *x509.Certificate
	CAs  *x509.CertPool
	PEM  []byte
	// PolicyPub is the pinned control-plane signing key (ENs only; nil otherwise).
	PolicyPub *ecdsa.PublicKey
}

func (i *Identity) TLS(serverName string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{i.Cert}, RootCAs: i.CAs, ServerName: serverName, MinVersion: tls.VersionTLS13}
}

func load(dir string) (*Identity, error) {
	kb, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	cb, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	pb, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	kblk, _ := pem.Decode(kb)
	cblk, _ := pem.Decode(cb)
	if kblk == nil || cblk == nil {
		return nil, errors.New("stored identity is unreadable")
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pb) {
		return nil, errors.New("stored CA is unreadable")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, errors.New("stored certificate expired; enrol again with a new token")
	}
	id := &Identity{Cert: tls.Certificate{Certificate: [][]byte{cblk.Bytes}, PrivateKey: key}, Leaf: leaf, CAs: pool, PEM: pb}
	if b, err := os.ReadFile(filepath.Join(dir, "policy.pub")); err == nil {
		if id.PolicyPub, err = pki.ParsePublicPEM(b); err != nil {
			return nil, fmt.Errorf("stored policy key is unreadable: %w", err)
		}
	}
	return id, nil
}

// LoadOrEnrol returns the identity stored in dir, or enrols with the one-time
// token at endpoint ("/enrol/connector" or "/enrol/en") and stores the result.
func LoadOrEnrol(dir, cpURL string, cpCA []byte, endpoint, token, name string) (*Identity, error) {
	if id, err := load(dir); err == nil {
		return id, nil
	}
	if token == "" {
		return nil, errors.New("no stored identity and no enrolment token supplied")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	body, _ := json.Marshal(map[string]string{"token": token, "name": name, "public_key": base64.StdEncoding.EncodeToString(pub)})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cpCA)
	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := cl.Post(strings.TrimSuffix(cpURL, "/")+endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, clockhint.Wrap(err, time.Now())
	}
	if sk, ok := clockhint.Skew(resp.Header, time.Now()); ok && clockhint.Wrong(sk) {
		fmt.Fprintln(os.Stderr, "WARNING: "+strings.Replace(clockhint.Plain(sk), "This computer's", "This machine's", 1))
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("enrolment failed (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}
	var out struct {
		Cert, CA  string
		PolicyPub string `json:"policy_pub"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(out.Cert)
	if err != nil {
		return nil, err
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	files := map[string][]byte{
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"ca.pem":   []byte(out.CA),
	}
	if out.PolicyPub != "" {
		files["policy.pub"] = []byte(out.PolicyPub)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			return nil, err
		}
	}
	return load(dir)
}

// HostOf returns the host part of a URL, for TLS server names.
func HostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Hostname()
}
