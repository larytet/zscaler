//go:build real

package real

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// startFull builds a world with a private app, a connector, an HTTPS origin and one agent, with TLS
// inspection on and the web policy allowing everything.
func startFull(t *testing.T) (*world, *agentInst) {
	w := newWorldN(t, 1, withWebSite)
	w.deployApp("erp")
	w.deployConnector("connector")
	w.deployOrigin()
	w.must("PUT", "/v1/inspection", map[string]any{"enabled": true})
	w.ifMatch = "1"
	w.putWebPolicy("allow", nil)
	a := w.newAgent("laptop", map[string]string{"erp.ztx": "erp"})
	steady(t, a, 60*time.Second, 2)
	return w, a
}

func percentile(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s)-1) * p)
	return s[i]
}

// REAL-OPS-001 (ADM-005, FW-010, ADM-007, NFR-033): every session has a record. The numbers are
// checked against what the app and the origin themselves saw, so a missing record cannot hide. No
// record, and nothing the admin API returns, holds payload content.
func TestRealOPS001DecisionRecordsAreCompleteAndHoldNoPayload(t *testing.T) {
	w, a := startFull(t)
	ca := w.inspectionPool()
	appBefore := len(w.appClients())
	seenBefore, _ := w.originSeen()
	countOpens := func(kind string, inspected bool) int {
		n := 0
		for _, d := range w.decisions() {
			if d["event"] == "open" && d["kind"] == kind && d["action"] == "allow" && (!inspected || d["inspected"] == true) {
				n++
			}
		}
		return n
	}
	privBase, webBase := countOpens("private", false), countOpens("web", true)

	const privateOK = 5
	for i := 0; i < privateOK; i++ {
		if !echoes(a.socks(), "erp.ztx", "PRIVATE-PAYLOAD-MARKER-7731") {
			t.Fatal("a private session failed")
		}
	}
	const webOK = 4
	for i := 0; i < webOK; i++ {
		if r := w.get(a, ca, "POST", "/log", "WEB-PAYLOAD-MARKER-5519", nil); r.code != 200 {
			t.Fatalf("a web request failed: %+v", r)
		}
	}
	w.putWebPolicy("allow", []map[string]any{{"id": "no-cards", "priority": 1, "action": "deny", "match": map[string]any{"dlp": []string{"credit-card"}}}})
	eventually(t, "the DLP rule to apply", 30*time.Second, func() bool {
		return w.get(a, ca, "POST", "/log", "4111 1111 1111 1111", nil).code == 403
	})
	w.ifMatch = "1"
	w.must("PUT", "/v1/policies/private", map[string]any{"default_action": "deny", "rules": []any{}})
	eventually(t, "private access to be refused", 30*time.Second, func() bool { return !echoes(a.socks(), "erp.ztx", "x") })
	time.Sleep(1500 * time.Millisecond)

	// independent counts: what the app and the origin saw
	appSaw := len(w.appClients()) - appBefore
	seen, _ := w.originSeen()
	// every request the origin received, whatever it was: while the DLP rule was still syncing the
	// first card-number probe was allowed through, and it has its own allow record like any other
	originSaw := len(seen) - len(seenBefore)
	privOpen, webOpen := countOpens("private", false)-privBase, countOpens("web", true)-webBase
	var denied, dlpDenied int
	for _, d := range w.decisions() {
		if d["event"] == "close" || d["event"] == nil {
			continue
		}
		switch d["kind"] {
		case "private":
			if d["action"] == "deny" {
				denied++
			}
		case "web":
			if d["action"] == "deny" && d["rule"] == "no-cards" {
				dlpDenied++
				if dl, _ := d["dlp"].([]any); len(dl) != 1 || dl[0] != "credit-card" {
					t.Errorf("the DLP record must name the data type: %v", d)
				}
			}
		}
	}
	if appSaw != privOpen {
		t.Errorf("the app saw %d connections but %d allow records exist: the log is not complete", appSaw, privOpen)
	}
	if originSaw < webOK || originSaw != webOpen {
		t.Errorf("the origin saw %d requests (we sent %d that were allowed); %d inspected allow records exist: the log is not complete", originSaw, webOK, webOpen)
	}
	if denied == 0 || dlpDenied == 0 {
		t.Errorf("denials are missing: private %d, DLP %d", denied, dlpDenied)
	}
	// every decision record carries who, from which device, what, which rule or reason, which policy version, and where
	for _, d := range w.decisions() {
		if d["kind"] != "private" && d["kind"] != "web" {
			continue
		}
		for _, f := range []string{"ts", "tenant", "user", "device", "action", "policy_version", "en"} {
			if d[f] == nil {
				t.Errorf("a decision record lacks %q: %v", f, d)
			}
		}
		if d["event"] != "close" && d["reason"] == nil && d["rule"] == nil {
			t.Errorf("a decision record has neither a rule nor a reason: %v", d)
		}
		if _, err := time.Parse(time.RFC3339Nano, d["ts"].(string)); err != nil {
			t.Errorf("bad timestamp %v", d["ts"])
		}
	}
	// the records are also kept on disk by the control plane for the retention period (six months by
	// default), and the history survives a restart of the control plane
	history := func() (opens int) {
		cursor := ""
		for i := 0; i < 50; i++ {
			_, b := w.api("GET", "/v1/decisions/history?kind=private&action=allow&limit=1000&cursor="+cursor, nil)
			var pg struct {
				Records []map[string]any
				Next    string `json:"next_cursor"`
				Days    int    `json:"retention_days"`
			}
			if err := json.Unmarshal(b, &pg); err != nil || pg.Days != 183 {
				t.Fatalf("history: %v %s", err, b)
			}
			for _, r := range pg.Records {
				if r["event"] == "open" {
					opens++
				}
			}
			if pg.Next == "" {
				break
			}
			cursor = pg.Next
		}
		return opens
	}
	if n := history(); n < privOpen {
		t.Errorf("the on-disk history has %d private allow records, the app saw %d connections", n, privOpen)
	}
	kept := history()
	w.cpProc.Process.Kill()
	w.cpProc.Wait()
	w.restartCP()
	if n := history(); n != kept {
		t.Errorf("the history changed across a control plane restart: %d before, %d after", kept, n)
	}

	// search through the admin API finds the same records, and no payload is in them
	_, sb := w.api("GET", "/v1/decisions?kind=private&action=deny&limit=500", nil)
	var found []map[string]any
	json.Unmarshal(sb, &found)
	if len(found) == 0 {
		t.Fatalf("the admin search returned no denials: %s", sb)
	}
	_, all := w.api("GET", "/v1/decisions?limit=500", nil)
	for _, secret := range []string{"PRIVATE-PAYLOAD-MARKER-7731", "WEB-PAYLOAD-MARKER-5519", "4111"} {
		if strings.Contains(string(all), secret) || strings.Contains(w.allDecisionsRaw(), secret) {
			t.Errorf("payload content %q is in the decision records", secret)
		}
	}
}

// REAL-PERF-001 (NFR-001, NFR-002, NFR-003): measured against the design targets, on this one machine.
// A miss fails the test and is recorded in RESULTS-REAL.md; it is not hidden.
func TestRealPERF001DesignTargets(t *testing.T) {
	w, a := startFull(t)
	ca := w.inspectionPool()

	// NFR-002: private-app session set-up after the first session, p95 under 500 ms
	var setup []time.Duration
	for i := 0; i < 60; i++ {
		start := time.Now()
		if !echoes(a.socks(), "erp.ztx", "p") {
			t.Fatal("a session failed during the measurement")
		}
		setup = append(setup, time.Since(start))
	}
	p50, p95 := percentile(setup, 0.5), percentile(setup, 0.95)
	t.Logf("REAL-PERF-001: private session set-up p50 %v, p95 %v over %d sessions (target p95 < 500 ms)", p50.Round(time.Millisecond), p95.Round(time.Millisecond), len(setup))
	if p95 >= 500*time.Millisecond {
		t.Errorf("NFR-002 missed: p95 %v", p95)
	}

	// NFR-003: throughput of one user through the connector, 100 Mbps or more
	c, err := socksConnect(a.socks(), "erp.ztx", 7000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const total = 64 << 20
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		n := 0
		for n < total {
			m, err := c.Read(buf)
			n += m
			if err != nil && n < total {
				done <- err
				return
			}
		}
		done <- nil
	}()
	start := time.Now()
	chunk := make([]byte, 64<<10)
	c.SetDeadline(time.Now().Add(120 * time.Second))
	for sent := 0; sent < total; sent += len(chunk) {
		if _, err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mbps := float64(total) * 8 / time.Since(start).Seconds() / 1e6
	t.Logf("REAL-PERF-001: %.0f Mbps echoed through the connector pod (one stream, both directions counted once; target >= 100 Mbps)", mbps)
	if mbps < 100 {
		t.Errorf("NFR-003 missed: %.0f Mbps", mbps)
	}

	// NFR-001: added latency for inspected web requests, p50 under 20 ms and p95 under 60 ms
	direct := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: w.site.pool}, DisableKeepAlives: true}}
	var viaPlatform, viaDirect []time.Duration
	for i := 0; i < 60; i++ {
		s := time.Now()
		if r := w.get(a, ca, "GET", "/p", "", nil); r.code != 200 {
			t.Fatalf("a web request failed: %+v", r)
		}
		viaPlatform = append(viaPlatform, time.Since(s))
		s = time.Now()
		resp, err := direct.Get("https://" + w.site.hostport + "/p")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		viaDirect = append(viaDirect, time.Since(s))
	}
	add50 := percentile(viaPlatform, 0.5) - percentile(viaDirect, 0.5)
	add95 := percentile(viaPlatform, 0.95) - percentile(viaDirect, 0.95)
	t.Logf("REAL-PERF-001: inspected web request, new connection each: direct p50 %v p95 %v; through the platform p50 %v p95 %v; added p50 %v p95 %v (targets < 20 ms and < 60 ms)",
		percentile(viaDirect, 0.5).Round(time.Millisecond), percentile(viaDirect, 0.95).Round(time.Millisecond),
		percentile(viaPlatform, 0.5).Round(time.Millisecond), percentile(viaPlatform, 0.95).Round(time.Millisecond), add50.Round(time.Millisecond), add95.Round(time.Millisecond))
	if add50 >= 20*time.Millisecond || add95 >= 60*time.Millisecond {
		t.Errorf("NFR-001 missed: added p50 %v, p95 %v", add50, add95)
	}
}

// REAL-SEC-001 (SEC-001..006, NFR-020): a stolen certificate without its key, a certificate from
// another authority and an old TLS version are all refused; a port outside an app's list is refused
// and the app is not contacted; no payload is written to the node's disk; key files are private.
func TestRealSEC001Security(t *testing.T) {
	w, a := startFull(t)
	ca := w.inspectionPool()
	broker := w.ens[0].brokerAddr(w)
	certDER := func() []byte {
		blk, _ := pem.Decode([]byte(mustRead(t, filepath.Join(a.dir, "device.crt"))))
		return blk.Bytes
	}()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(mustRead(t, w.caPath)))
	handshake := func(cfg *tls.Config) error {
		cfg.RootCAs, cfg.ServerName = pool, w.hostIP
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", broker, cfg)
		if err != nil {
			return err
		}
		defer c.Close()
		// TLS 1.3 reports a rejected client certificate on the first read
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = c.Read(make([]byte, 1))
		if err != nil && strings.Contains(err.Error(), "i/o timeout") {
			return nil // the server kept the connection open: it was accepted
		}
		return err
	}
	// 1. the right certificate but someone else's key (a stolen certificate)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := handshake(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: other}}}); err == nil {
		t.Error("SEC-001: a certificate without its key was accepted")
	}
	// 2. a certificate from another authority
	fk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t1/u1/d-forged"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	fder, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &fk.PublicKey, fk)
	if err := handshake(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{fder}, PrivateKey: fk}}}); err == nil {
		t.Error("SEC-004: a certificate from another authority was accepted")
	}
	// 3. no certificate at all
	if err := handshake(&tls.Config{}); err == nil {
		t.Error("a client without a certificate was accepted")
	}
	// 4. an old TLS version
	if err := handshake(&tls.Config{MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("SEC-011: TLS 1.1 was accepted")
	}

	// 5. a port outside the app's list is refused and the app is not contacted
	before := len(w.appClients())
	if c, err := socksConnect(a.socks(), "erp.ztx", 2222); err == nil {
		c.Close()
		t.Error("a port outside the app's list was opened")
	}
	if n := len(w.appClients()); n != before {
		t.Errorf("the app was contacted for a port that is not in its list (%d connections)", n-before)
	}
	found := false
	eventually(t, "the refusal of the unlisted port to be recorded", 15*time.Second, func() bool {
		for _, d := range w.decisions() {
			if d["kind"] == "private" && d["action"] == "deny" && d["reason"] == "target-not-in-segment" {
				found = true
			}
		}
		return found
	})

	// 6. the admin API needs a token
	req, _ := http.NewRequest("GET", w.adminU+"/v1/decisions", nil)
	if resp, err := w.admin.Do(req); err != nil || resp.StatusCode != 401 {
		t.Errorf("the admin API answered a request with no token: %v %v", resp, err)
	}

	// 7. no payload on disk (NFR-020), and key files are private
	echoes(a.socks(), "erp.ztx", "DISK-PAYLOAD-MARKER-9042")
	w.get(a, ca, "POST", "/disk", "DISK-PAYLOAD-MARKER-9042", nil)
	time.Sleep(1500 * time.Millisecond)
	filepath.Walk(w.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), "DISK-PAYLOAD-MARKER-9042") {
			t.Errorf("NFR-020: payload content found in %s", p)
		}
		if strings.HasSuffix(p, ".key") && info.Mode().Perm()&0o077 != 0 {
			t.Errorf("key file %s is readable by others (%v)", p, info.Mode().Perm())
		}
		return nil
	})
}
