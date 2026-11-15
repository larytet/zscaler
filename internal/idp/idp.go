// Package idp verifies OIDC ID tokens (DESIGN.md D4.2). Only RS256 and ES256
// are accepted; "none" and HMAC algorithms are rejected.
package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	Tolerance      = 2 * time.Minute
	minRefreshWait = 10 * time.Second
)

type Claims struct {
	Subject       string
	Email         string
	EmailVerified *bool
	Groups        []string
	Nonce         string
	Expires       time.Time
}

type Verifier struct {
	Issuer     string
	ClientID   string
	GroupClaim string
	HTTP       *http.Client
	Now        func() time.Time

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	jwksURI     string
	lastRefresh time.Time
	Refreshes   int // counted for tests
}

var ErrToken = errors.New("idp: invalid token")

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) client() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

var b64 = base64.RawURLEncoding

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify checks signature, issuer, audience, expiry and nonce. wantNonce must be non-empty.
func (v *Verifier) Verify(token, wantNonce string) (*Claims, error) {
	if wantNonce == "" {
		return nil, fmt.Errorf("%w: nonce required", ErrToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrToken
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrToken
	}
	var h header
	if json.Unmarshal(hb, &h) != nil || (h.Alg != "RS256" && h.Alg != "ES256") {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrToken)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrToken
	}
	key, err := v.key(h.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, fmt.Errorf("%w: bad signature", ErrToken)
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, fmt.Errorf("%w: bad signature", ErrToken)
		}
	default:
		return nil, ErrToken
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrToken
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(pb, &raw) != nil {
		return nil, ErrToken
	}
	str := func(k string) string { var s string; json.Unmarshal(raw[k], &s); return s }
	if str("iss") != v.Issuer {
		return nil, fmt.Errorf("%w: wrong issuer", ErrToken)
	}
	if !audOK(raw["aud"], v.ClientID) {
		return nil, fmt.Errorf("%w: wrong audience", ErrToken)
	}
	var exp float64
	if json.Unmarshal(raw["exp"], &exp) != nil || exp == 0 {
		return nil, fmt.Errorf("%w: missing exp", ErrToken)
	}
	expires := time.Unix(int64(exp), 0)
	if v.now().After(expires.Add(Tolerance)) {
		return nil, fmt.Errorf("%w: expired", ErrToken)
	}
	var nbf float64
	if json.Unmarshal(raw["nbf"], &nbf) == nil && nbf != 0 && v.now().Add(Tolerance).Before(time.Unix(int64(nbf), 0)) {
		return nil, fmt.Errorf("%w: not yet valid", ErrToken)
	}
	if str("nonce") != wantNonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrToken)
	}
	c := &Claims{Subject: str("sub"), Email: str("email"), Nonce: str("nonce"), Expires: expires}
	if c.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrToken)
	}
	var ev bool
	if json.Unmarshal(raw["email_verified"], &ev) == nil {
		c.EmailVerified = &ev
		if !ev {
			return nil, fmt.Errorf("%w: email not verified", ErrToken)
		}
	}
	gc := v.GroupClaim
	if gc == "" {
		gc = "groups"
	}
	json.Unmarshal(raw[gc], &c.Groups)
	return c, nil
}

func audOK(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// key returns the key for kid, refreshing the JWKS at most once per
// minRefreshWait when the kid is unknown.
func (v *Verifier) key(kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if v.keys != nil && v.now().Sub(v.lastRefresh) < minRefreshWait {
		return nil, fmt.Errorf("%w: unknown key id", ErrToken)
	}
	if err := v.refresh(); err != nil {
		return nil, err
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown key id", ErrToken)
}

func (v *Verifier) get(url string, out any) error {
	resp, err := v.client().Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("idp: %s returned %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (v *Verifier) refresh() error {
	v.lastRefresh = v.now()
	v.Refreshes++
	if v.jwksURI == "" {
		var d struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.get(strings.TrimSuffix(v.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
			return err
		}
		if d.Issuer != v.Issuer || d.JWKSURI == "" {
			return errors.New("idp: discovery document does not match issuer")
		}
		v.jwksURI = d.JWKSURI
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	if err := v.get(v.jwksURI, &set); err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, e := dec(k.N), dec(k.E)
			if n != nil && e != nil && e.IsInt64() {
				keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
			}
		case "EC":
			x, y := dec(k.X), dec(k.Y)
			if k.Crv == "P-256" && x != nil && y != nil {
				pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
				if _, err := pk.ECDH(); err == nil { // validates that the point is on the curve
					keys[k.Kid] = pk
				}
			}
		}
	}
	if len(keys) == 0 {
		return errors.New("idp: no usable keys in JWKS")
	}
	v.keys = keys
	return nil
}

func dec(s string) *big.Int {
	b, err := b64.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(b)
}
