package cp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/policy"
	"github.com/larytet/zscaler/internal/privacy"
	"github.com/larytet/zscaler/internal/siem"
	"github.com/larytet/zscaler/internal/store"
)

func TestPrivacyModeHidesNamesInStoredStreamedAndShownLogs(t *testing.T) { // AGT-027 (NFR-033, ADM-006b)
	e := newEnrolEnv(t)
	e.api.Decisions = decisions.New()
	dir := filepath.Join(t.TempDir(), "d")
	arch, _ := decisions.OpenArchive(dir, decisions.DefaultRetention)
	defer arch.Close()
	e.api.Decisions.SetArchive(arch)
	e.api.SIEM = &siem.Streamer{AllowLoopback: true, Backoff: 20 * time.Millisecond}
	defer e.api.SIEM.Configure("a", nil)
	rcv := newSink(t)
	e.call("PUT", "/v1/siem", e.adminA, map[string]any{"kind": "https", "url": rcv.srv.URL, "ca_pem": rcv.ca(), "audit": false})
	e.api.Store.UpsertUser("a", policy.User{Subject: "alice", Email: "alice@example.com"})
	e.api.Store.UpsertUser("a", policy.User{Subject: "bob", Email: "bob@example.com"})

	now := time.Now().UTC()
	ingest := func(users ...string) {
		var recs []broker.Record
		for _, u := range users {
			recs = append(recs, broker.Record{Tenant: "a", Kind: "private", Action: "allow", Event: "open", User: u, App: "erp", TS: now})
		}
		if c, _ := e.post("/ingest/records", recs, enCert(t, e)); c != 200 {
			t.Fatalf("ingest %d", c)
		}
	}
	list := func(q string) string { _, b, _ := e.call("GET", "/v1/decisions"+q, e.adminA, nil); return string(b) }
	history := func(q string) string {
		_, b, _ := e.call("GET", "/v1/decisions/history"+q, e.adminA, nil)
		return string(b)
	}

	ingest("alice") // before the mode is on
	if !strings.Contains(list(""), `"alice"`) {
		t.Fatal("with the mode off the names are shown")
	}
	c, b, _ := e.call("PUT", "/v1/privacy", e.adminA, map[string]any{"pseudonymise_users": true})
	if c != 200 || !strings.Contains(string(b), `"pseudonymise_users":true`) || strings.Contains(string(b), "key") {
		t.Fatalf("%d %s", c, b)
	}
	ingest("alice", "bob", "agent:helper")

	// shown: no name anywhere, the same pseudonym for the same person, the agent keeps its name
	for _, body := range []string{list(""), history("?limit=1000")} {
		if strings.Contains(body, "alice") || strings.Contains(body, "bob") {
			t.Fatalf("a name was shown: %s", body)
		}
		if !strings.Contains(body, "agent:helper") {
			t.Fatalf("an AI agent is not a person and keeps its name: %s", body)
		}
	}
	key := e.api.Store.Privacy("a").Key
	pa, pb := privacy.Pseudonym(key, "alice"), privacy.Pseudonym(key, "bob")
	if n := strings.Count(history("?limit=1000"), pa); n != 2 || strings.Contains(history("?limit=1000"), "u-000000000000") {
		t.Fatalf("alice's two records (one stored before the mode) must carry one pseudonym: %d", n)
	}

	// stored: what went to disk after the mode was turned on has no name; the live view still does (risk and alerts need it)
	raw := ""
	filepath.Walk(dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			x, _ := os.ReadFile(p)
			raw += string(x)
		}
		return nil
	})
	if n := strings.Count(raw, `"user":"alice"`); n != 1 { // the one record stored before
		t.Fatalf("on disk, alice appears by name %d times; only the record from before the mode may", n)
	}
	if strings.Contains(raw, `"user":"bob"`) {
		t.Fatal("bob's record was stored with his name")
	}
	if es, _ := e.api.Decisions.Query("a", decisions.Filter{User: "bob", Limit: 10}); len(es) != 1 {
		t.Fatal("the live view must keep real names: risk scores and alerts are computed from it")
	}

	// streamed
	until(t, "the streamed decisions", func() bool { return rcv.types()["decision"] >= 4 })
	named := 0
	rcv.mu.Lock()
	for _, ev := range rcv.events {
		if ev["type"] == "decision" && (ev["user"] == "alice" || ev["user"] == "bob") {
			named++
			if ev["user"] == "bob" {
				t.Error("bob was streamed by name after the mode was turned on")
			}
		}
	}
	rcv.mu.Unlock()
	if named != 1 { // only the record that was streamed before the mode was turned on
		t.Fatalf("%d decisions were streamed with a name", named)
	}
	if !rcv.has(func(m map[string]any) bool { return m["user"] == pb }) {
		t.Fatalf("bob's pseudonym was not streamed: %v", rcv.events)
	}

	// a real name finds nothing, a pseudonym finds the person's records (also the older one)
	if got := list("?user=alice"); strings.Contains(got, pa) || got != "[]\n" {
		t.Fatalf("a real name must find nothing in privacy mode: %s", got)
	}
	var h struct{ Records []broker.Record }
	json.Unmarshal([]byte(history("?user=alice&limit=1000")), &h)
	if len(h.Records) != 0 {
		t.Fatalf("a real name found %d archived records", len(h.Records))
	}
	json.Unmarshal([]byte(history("?user="+pa+"&limit=1000")), &h)
	if len(h.Records) != 2 {
		t.Fatalf("the pseudonym should find both of alice's records, found %d", len(h.Records))
	}
	if strings.Count(list("?user="+pa), pa) != 2 {
		t.Fatalf("the live list by pseudonym: %s", list("?user="+pa))
	}

	// look-up: owners only, audited without the name
	if c, b, _ := e.call("GET", "/v1/privacy/reveal?pseudonym="+pa, e.adminA, nil); c != 200 || !strings.Contains(string(b), `"user":"alice"`) {
		t.Fatalf("%d %s", c, b)
	}
	adm, _ := e.api.Store.AddAdmin("a", "adam", store.Admin)
	hd, _ := e.api.Store.AddAdmin("a", "hank", store.Helpdesk)
	for _, tok := range []string{adm, hd} {
		if c, _, _ := e.call("GET", "/v1/privacy/reveal?pseudonym="+pa, tok, nil); c != 403 {
			t.Fatalf("a non-owner looked a pseudonym up: %d", c)
		}
	}
	for q, want := range map[string]int{"?pseudonym=alice": 400, "?pseudonym=": 400, "?pseudonym=u-ffffffffffff": 404} {
		if c, _, _ := e.call("GET", "/v1/privacy/reveal"+q, e.adminA, nil); c != want {
			t.Errorf("%s: %d, want %d", q, c, want)
		}
	}
	if _, ab, _ := e.call("GET", "/v1/audit", e.adminA, nil); !strings.Contains(string(ab), "privacy.reveal") || !strings.Contains(string(ab), pa) || strings.Contains(string(ab), "alice@example.com") {
		t.Fatalf("a look-up must be audited with the pseudonym and not the name: %s", ab)
	}
	// roles and tenant isolation
	viewer, _ := e.api.Store.AddAdmin("a", "vera", store.Viewer)
	if c, _, _ := e.call("PUT", "/v1/privacy", viewer, map[string]any{"pseudonymise_users": false}); c != 403 {
		t.Fatalf("a viewer changed the mode: %d", c)
	}
	if c, b, _ := e.call("GET", "/v1/privacy", viewer, nil); c != 200 || !strings.Contains(string(b), `"pseudonymise_users":true`) {
		t.Fatalf("%d %s", c, b)
	}
	if _, b, _ := e.call("GET", "/v1/privacy", e.adminB, nil); !strings.Contains(string(b), `"pseudonymise_users":false`) {
		t.Fatalf("tenant b: %s", b)
	}
	if c, _, _ := e.call("PUT", "/v1/privacy", e.adminA, map[string]any{}); c != 400 {
		t.Fatalf("a missing value: %d", c)
	}

	// off again: names are shown again, and the key is kept so old pseudonyms can still be looked up
	e.call("PUT", "/v1/privacy", e.adminA, map[string]any{"pseudonymise_users": false})
	if !strings.Contains(list(""), `"alice"`) {
		t.Fatal("names must be shown again when the mode is off")
	}
	if c, _, _ := e.call("GET", "/v1/privacy/reveal?pseudonym="+pa, e.adminA, nil); c != 200 {
		t.Fatalf("the key must be kept: %d", c)
	}
}
