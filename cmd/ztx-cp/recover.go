package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/incident"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

// resetOwner is the way back in when every owner token is lost (GAP-REQ-03). It needs the server's own data
// directory, and the master key when the data is encrypted, so it is as hard to do as reading the data. It
// replaces the token of the named owner, or makes an owner of that name if there is none, prints the new
// token once, and records the act in the audit chain under the name of the person at the server's command
// line. The weekly digest then lists it as an owner reset from the server, so someone who did not do it
// sees it. Stop the control plane first.
func resetOwner(dir string, key *seal.Key, tenant, name, hostUser string, now time.Time) (string, error) {
	st, err := store.OpenWithKey(filepath.Join(dir, "store.json"), key)
	if err != nil {
		return "", err
	}
	st.Now = func() time.Time { return now }
	known := false
	for _, t := range st.Tenants() {
		known = known || t == tenant
	}
	if !known {
		return "", fmt.Errorf("no tenant %q (run with -list to see them)", tenant)
	}
	var existing *store.AdminInfo
	for _, a := range st.Admins(tenant) {
		if a.Name == name {
			a := a
			existing = &a
		}
	}
	var tok string
	switch {
	case existing == nil:
		tok, err = st.AddAdmin(tenant, name, store.Owner)
	case existing.Role != store.Owner:
		return "", fmt.Errorf("%q is an administrator with the role %s: this command does not change roles; choose another name or an owner's name (-list shows them)", name, existing.Role)
	default:
		tok, err = st.RotateAdmin(tenant, name)
	}
	if err != nil {
		return "", err
	}
	lg, err := audit.Open(filepath.Join(dir, "audit.jsonl"), func() time.Time { return now })
	if err != nil {
		return "", fmt.Errorf("the owner token was changed but the audit log could not be opened: %w", err)
	}
	defer lg.Close()
	how := "replaced the token of an existing owner"
	if existing == nil {
		how = "made a new owner"
	}
	if _, err := lg.Append(tenant, "host:"+hostUser, "owner.reset", name, nil, map[string]string{"how": "ztx-cp reset-owner at the server", "result": how}); err != nil {
		return "", fmt.Errorf("the owner token was changed but the audit log could not be written: %w", err)
	}
	return tok, nil
}

// listAccess shows the tenants and the administrator names, never a token, for someone who has lost them.
func listAccess(dir string, key *seal.Key) error {
	st, err := store.OpenWithKey(filepath.Join(dir, "store.json"), key)
	if err != nil {
		return err
	}
	for _, t := range st.Tenants() {
		fmt.Printf("tenant %s\n", t)
		for _, a := range st.Admins(t) {
			fmt.Printf("  %-20s %s\n", a.Name, a.Role)
		}
	}
	return nil
}

func runRecoverCommand(args []string) bool {
	if len(args) > 0 && args[0] == "incident-report" {
		runIncidentReport(args[1:])
		return true
	}
	if len(args) == 0 || args[0] != "reset-owner" {
		return false
	}
	fs := flag.NewFlagSet("reset-owner", flag.ExitOnError)
	data := fs.String("data", "cp-data", "control plane data directory (stop the control plane first)")
	tenant := fs.String("tenant", "", "the tenant")
	name := fs.String("name", "owner", "the owner to replace the token of (or to make, if there is none of that name)")
	list := fs.Bool("list", false, "list the tenants and administrator names, and do nothing else")
	keyFile := fs.String("master-key-file", "", "file holding the master key if the data is encrypted (or ZTX_MASTER_KEY)")
	fs.Parse(args[1:])
	key, err := masterKey(*keyFile)
	check(err)
	if *list {
		check(listAccess(*data, key))
		return true
	}
	if *tenant == "" {
		check(errors.New("-tenant is required (-list shows the tenants)"))
	}
	hu := "unknown"
	if u, err := user.Current(); err == nil {
		hu = u.Username
	}
	if _, err := os.Stat(filepath.Join(*data, "store.json")); err != nil {
		check(fmt.Errorf("%s is not a control plane data directory", *data))
	}
	tok, err := resetOwner(*data, key, *tenant, *name, hu, time.Now())
	check(err)
	fmt.Printf("owner %q of tenant %q now has this token (shown once):\n%s\n", *name, *tenant, tok)
	fmt.Println("The act is in the audit log and in the next weekly summary. Other administrators' tokens were not touched: if you think they leaked too, replace them (POST /v1/admins/{name}/rotate).")
	return true
}

// runIncidentReport prints which tenants are in scope after a loss of data, what is held about each, who to tell
// and by when (GAP-REQ-11). It reads the data directory and changes nothing, so it is safe while the control
// plane runs.
func runIncidentReport(args []string) {
	fs := flag.NewFlagSet("incident-report", flag.ExitOnError)
	data := fs.String("data", "cp-data", "control plane data directory")
	keyFile := fs.String("master-key-file", "", "file holding the master key if the data is encrypted (or ZTX_MASTER_KEY)")
	scen := fs.String("scenario", "control-plane", "what was lost: control-plane (the server, its disk or a backup), node:<name> (an enforcement node) or admin-token:<tenant>")
	fromS := fs.String("from", "", "start of the window, RFC 3339 (default: 30 days ago)")
	toS := fs.String("to", "", "end of the window, RFC 3339 (default: now)")
	awareS := fs.String("aware", "", "when you became aware of the incident, RFC 3339: prints the 72-hour reminder")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	fs.Parse(args)
	key, err := masterKey(*keyFile)
	check(err)
	st, err := store.OpenWithKey(filepath.Join(*data, "store.json"), key)
	check(err)
	now := time.Now()
	parse := func(name, v string, def time.Time) time.Time {
		if v == "" {
			return def
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			check(fmt.Errorf("-%s: %q is not an RFC 3339 time such as 2026-11-15T09:30:00Z", name, v))
		}
		return t
	}
	sc := incident.Scenario{Kind: *scen}
	if n, ok := strings.CutPrefix(*scen, "node:"); ok {
		sc = incident.Scenario{Kind: "node", Node: n}
	} else if t, ok := strings.CutPrefix(*scen, "admin-token:"); ok {
		sc = incident.Scenario{Kind: "admin-token", Tenant: t}
	}
	rep, err := incident.Build(st, *data, key, sc, parse("from", *fromS, now.AddDate(0, 0, -30)), parse("to", *toS, now), parse("aware", *awareS, time.Time{}), now)
	check(err)
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", " ")
		fmt.Println(string(b))
		return
	}
	fmt.Print(rep.Text())
}
