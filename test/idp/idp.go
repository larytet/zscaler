// Package idp is an in-process OIDC provider for tests: discovery, JWKS with
// rotation, and ID tokens that can be made deliberately bad.
package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	*httptest.Server
	ClientID string
	JWKSHits atomic.Int64

	// Login is the identity returned by the authorization flow.
	Sub, Email string
	Groups     []string
	// SkipPKCECheck makes /token accept any code_verifier (to test that the client sends one).
	SkipPKCECheck bool

	codes map[string]authCode
	mu    sync.Mutex
	keys  map[string]*ecdsa.PrivateKey // advertised in JWKS
	rsa   map[string]*rsa.PrivateKey
}

var b64 = base64.RawURLEncoding

func New(clientID string) *Server {
	s := &Server{ClientID: clientID, Sub: "u1", Email: "u1@example.com", Groups: []string{"all-staff"}, codes: map[string]authCode{}, keys: map[string]*ecdsa.PrivateKey{}, rsa: map[string]*rsa.PrivateKey{}}
	s.AddKey("k1")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": s.URL, "jwks_uri": s.URL + "/jwks",
			"authorization_endpoint": s.URL + "/authorize", "token_endpoint": s.URL + "/token"})
	})
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		s.JWKSHits.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		var ks []map[string]string
		for kid, k := range s.keys {
			ks = append(ks, map[string]string{"kty": "EC", "crv": "P-256", "kid": kid,
				"x": b64.EncodeToString(k.X.FillBytes(make([]byte, 32))), "y": b64.EncodeToString(k.Y.FillBytes(make([]byte, 32)))})
		}
		for kid, k := range s.rsa {
			ks = append(ks, map[string]string{"kty": "RSA", "kid": kid, "n": b64.EncodeToString(k.N.Bytes()),
				"e": b64.EncodeToString([]byte{1, 0, 1})})
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	})
	s.Server = httptest.NewServer(mux)
	return s
}

// AddKey advertises a new EC key under kid (rotation).
func (s *Server) AddKey(kid string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.mu.Lock()
	s.keys[kid] = k
	s.mu.Unlock()
}

func (s *Server) AddRSAKey(kid string) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	s.mu.Lock()
	s.rsa[kid] = k
	s.mu.Unlock()
}

func (s *Server) RemoveKey(kid string) {
	s.mu.Lock()
	delete(s.keys, kid)
	delete(s.rsa, kid)
	s.mu.Unlock()
}

// Claims is a mutable template for a token.
type Claims map[string]any

func (s *Server) Good(sub, email, nonce string, groups ...string) Claims {
	return Claims{"iss": s.URL, "aud": s.ClientID, "sub": sub, "email": email, "email_verified": true,
		"nonce": nonce, "exp": float64(time.Now().Add(time.Hour).Unix()), "groups": groups}
}

// Sign signs with the advertised key kid using ES256 (or RS256 when the kid is an RSA key).
func (s *Server) Sign(kid string, c Claims) string {
	s.mu.Lock()
	ek, isEC := s.keys[kid]
	rk := s.rsa[kid]
	s.mu.Unlock()
	alg := "ES256"
	if !isEC {
		alg = "RS256"
	}
	return s.signWith(alg, kid, c, ek, rk)
}

// SignUnadvertised signs with a fresh key that is not in the JWKS.
func (s *Server) SignUnadvertised(kid string, c Claims) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return s.signWith("ES256", kid, c, k, nil)
}

// SignAlg lets a test claim any alg, for example "none" or "HS256".
func (s *Server) SignAlg(alg, kid string, c Claims) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid})
	p, _ := json.Marshal(c)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "." + b64.EncodeToString([]byte("x"))
}

func (s *Server) signWith(alg, kid string, c Claims, ek *ecdsa.PrivateKey, rk *rsa.PrivateKey) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid})
	p, _ := json.Marshal(c)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	if alg == "ES256" {
		r, ss, _ := ecdsa.Sign(rand.Reader, ek, d[:])
		sig = append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	} else {
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, d[:])
		if err != nil {
			panic(fmt.Sprint(err))
		}
	}
	return in + "." + b64.EncodeToString(sig)
}

type authCode struct{ challenge, nonce, redirect string }

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != s.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		http.Error(w, "bad authorization request", 400)
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	code := b64.EncodeToString(b)
	s.mu.Lock()
	s.codes[code] = authCode{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")}
	s.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.mu.Lock()
	ac, ok := s.codes[r.Form.Get("code")]
	delete(s.codes, r.Form.Get("code")) // single use
	s.mu.Unlock()
	if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != s.ClientID || r.Form.Get("redirect_uri") != ac.redirect {
		http.Error(w, `{"error":"invalid_grant"}`, 400)
		return
	}
	h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !s.SkipPKCECheck && b64.EncodeToString(h[:]) != ac.challenge {
		http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, 400)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"id_token": s.Sign("k1", s.Good(s.Sub, s.Email, ac.nonce, s.Groups...)), "token_type": "Bearer"})
}
