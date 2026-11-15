// Package agent is the endpoint agent: OIDC login, device certificate,
// local proxies and posture reporting (DESIGN.md D4).
package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

func randStr(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// LoginResult is what the control plane needs to verify the user.
type LoginResult struct {
	IDToken string
	Nonce   string
}

// Login runs the OIDC authorization-code flow with PKCE (S256) in the
// system browser. openURL launches the browser; tests pass a function that
// follows the redirect directly.
func Login(ctx context.Context, issuer, clientID string, openURL func(string) error) (*LoginResult, error) {
	hc := &http.Client{Timeout: 15 * time.Second}
	var disc struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if err := getJSON(hc, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &disc); err != nil {
		return nil, err
	}
	if disc.Issuer != issuer || disc.Auth == "" || disc.Token == "" {
		return nil, errors.New("agent: discovery document does not match the configured issuer")
	}
	state, nonce, verifier := randStr(24), randStr(24), randStr(48)
	ch := sha256.Sum256([]byte(verifier))

	ln, err := net.Listen("tcp", "127.0.0.1:0") // loopback only (SEC-016)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	redirect := "http://" + ln.Addr().String() + "/callback"

	type cb struct {
		code string
		err  error
	}
	done := make(chan cb, 1)
	var used bool
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" || used {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return // keep waiting for the real callback; a forged one changes nothing
		}
		used = true
		if e := q.Get("error"); e != "" {
			http.Error(w, "login failed", 400)
			done <- cb{err: fmt.Errorf("agent: login error from IdP: %s", e)}
			return
		}
		io.WriteString(w, "Signed in. You can close this window.")
		done <- cb{code: q.Get("code")}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	au, _ := url.Parse(disc.Auth)
	v := au.Query()
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirect)
	v.Set("scope", "openid email profile groups")
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("code_challenge", b64.EncodeToString(ch[:]))
	v.Set("code_challenge_method", "S256")
	au.RawQuery = v.Encode()
	if err := openURL(au.String()); err != nil {
		return nil, err
	}
	var got cb
	select {
	case got = <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, errors.New("agent: login timed out")
	}
	if got.err != nil {
		return nil, got.err
	}
	resp, err := hc.PostForm(disc.Token, url.Values{"grant_type": {"authorization_code"}, "code": {got.code},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("agent: token endpoint returned %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil || tr.IDToken == "" {
		return nil, errors.New("agent: no id_token in token response")
	}
	return &LoginResult{IDToken: tr.IDToken, Nonce: nonce}, nil
}

func getJSON(c *http.Client, u string, out any) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("agent: %s returned %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
