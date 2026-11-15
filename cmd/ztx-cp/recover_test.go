package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

func setup(t *testing.T, key *seal.Key) (dir, ownerTok, carolTok string) {
	t.Helper()
	dir = t.TempDir()
	st, err := store.OpenWithKey(filepath.Join(dir, "store.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	ownerTok, err = st.CreateTenant("acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	carolTok, _ = st.AddAdmin("acme", "carol", store.Helpdesk)
	st.CreateTenant("other", "Other")
	return
}

// The way back in when every owner token is lost needs the server, leaves a trace, and changes nothing else (GAP-REQ-03).
func TestResetOwnerIsTheWayBackInAndLeavesATrace(t *testing.T) { // AGT-043
	for _, sealed := range []bool{false, true} {
		var key *seal.Key
		if sealed {
			key = mk(t)
		}
		dir, oldOwner, carol := setup(t, key)
		now := time.Now().UTC()
		tok, err := resetOwner(dir, key, "acme", "owner", "alice-at-the-server", now)
		if err != nil || tok == "" || tok == oldOwner {
			t.Fatalf("sealed=%v: %v %q", sealed, err, tok)
		}
		st, err := store.OpenWithKey(filepath.Join(dir, "store.json"), key)
		if err != nil {
			t.Fatal(err)
		}
		if tn, role, name, ok := st.Auth(tok); !ok || tn != "acme" || role != store.Owner || name != "owner" {
			t.Errorf("the new token: %v %v %v %v", tn, role, name, ok)
		}
		if _, _, _, ok := st.Auth(oldOwner); ok {
			t.Error("the lost token still works: the lost token may be in someone else's hands")
		}
		if _, role, _, ok := st.Auth(carol); !ok || role != store.Helpdesk {
			t.Error("another administrator was touched")
		}
		// another tenant is not given an owner by this
		for _, a := range st.Admins("other") {
			if a.Name != "owner" {
				t.Errorf("other tenant: %+v", a)
			}
		}
		// the trace: in the chain, under the name of the person at the server, and the chain still verifies
		ap := filepath.Join(dir, "audit.jsonl")
		if n, err := audit.Verify(ap); err != nil || n != 1 {
			t.Fatalf("audit chain: %d %v", n, err)
		}
		ev, _ := audit.ReadAll(ap, "acme")
		if len(ev) != 1 || ev[0].Action != "owner.reset" || ev[0].Actor != "host:alice-at-the-server" || ev[0].Object != "owner" {
			t.Fatalf("audit: %+v", ev)
		}
		if strings.Contains(string(ev[0].After), tok) {
			t.Error("the token is in the audit log")
		}
		// a second reset appends to the same chain
		if _, err := resetOwner(dir, key, "acme", "owner", "bob", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if n, err := audit.Verify(ap); err != nil || n != 2 {
			t.Errorf("after a second reset: %d %v", n, err)
		}
	}
}

func TestResetOwnerRefusesWhatItShouldNot(t *testing.T) { // AGT-043
	key := mk(t)
	dir, _, carol := setup(t, key)
	now := time.Now()
	if _, err := resetOwner(dir, key, "nope", "owner", "x", now); err == nil || !strings.Contains(err.Error(), "-list") {
		t.Errorf("an unknown tenant: %v", err)
	}
	// it does not promote an existing helpdesk administrator by name
	if _, err := resetOwner(dir, key, "acme", "carol", "x", now); err == nil || !strings.Contains(err.Error(), "does not change roles") {
		t.Errorf("a non-owner name: %v", err)
	}
	st, _ := store.OpenWithKey(filepath.Join(dir, "store.json"), key)
	if _, role, _, ok := st.Auth(carol); !ok || role != store.Helpdesk {
		t.Error("a refused reset changed an administrator")
	}
	// without the key, or with a wrong one, the encrypted data cannot be touched, and nothing is written
	if _, err := resetOwner(dir, nil, "acme", "owner", "x", now); err == nil {
		t.Error("an encrypted store was opened without its key")
	}
	if _, err := resetOwner(dir, mk(t), "acme", "owner", "x", now); err == nil {
		t.Error("an encrypted store was opened with a wrong key")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err == nil {
		t.Error("an audit record was written by a refused reset")
	}
	// a name with no owner of that name makes a new owner
	tok, err := resetOwner(dir, key, "acme", "recovery-owner", "x", now)
	if err != nil {
		t.Fatal(err)
	}
	st, _ = store.OpenWithKey(filepath.Join(dir, "store.json"), key)
	if _, role, name, ok := st.Auth(tok); !ok || role != store.Owner || name != "recovery-owner" {
		t.Errorf("new owner: %v %v %v", role, name, ok)
	}
}
