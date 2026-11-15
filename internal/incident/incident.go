// Package incident answers the first questions after the platform may have lost data (GAP-REQ-11): which
// tenants are affected, what kinds of their data the platform holds, who to tell, and by when. It reads the
// store, the decision archive and the audit chain and changes nothing.
//
// What it cannot answer: whether anything was READ. Reads are not recorded anywhere (the audit log holds
// changes made by administrators, the decision records hold access decisions), so the honest working
// assumption after a theft of the control plane's data is that everything listed was exposed.
package incident

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/decisions"
	"github.com/larytet/zscaler/internal/seal"
	"github.com/larytet/zscaler/internal/store"
)

// Scenario says what was lost.
type Scenario struct {
	Kind   string // "control-plane" (the server or its data directory or a backup), "node" or "admin-token"
	Node   string // the enforcement node's name, for "node"
	Tenant string // the tenant, for "admin-token"
}

type Category struct {
	What  string `json:"what"`
	Count int    `json:"count"`
	Note  string `json:"note,omitempty"`
}

type TenantReport struct {
	Tenant       string         `json:"tenant"`
	Name         string         `json:"name"`
	Affected     bool           `json:"affected"`
	Why          string         `json:"why"`
	Contact      string         `json:"security_contact"`
	ContactName  string         `json:"security_contact_name,omitempty"`
	FallbackTo   []string       `json:"alert_recipients_if_no_contact,omitempty"`
	Categories   []Category     `json:"data_held"`
	ArchiveDays  int            `json:"decision_record_days"`
	ArchiveFrom  string         `json:"decision_records_from,omitempty"`
	ArchiveTo    string         `json:"decision_records_to,omitempty"`
	AuditActions int            `json:"admin_actions_in_window"`
	AuditActors  map[string]int `json:"admin_actions_by_actor,omitempty"`
}

type Report struct {
	Scenario    Scenario       `json:"scenario"`
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	Aware       time.Time      `json:"aware,omitempty"`
	Deadline    time.Time      `json:"notify_authority_by,omitempty"`
	Sealed      bool           `json:"store_encrypted_at_rest"`
	AuditOK     string         `json:"audit_chain"`
	Tenants     []TenantReport `json:"tenants"`
	CannotTell  []string       `json:"cannot_be_told"`
	GeneratedAt time.Time      `json:"generated_at"`
}

// NotifyWithin is the period the GDPR gives to tell the supervisory authority (Article 33). It is stated here
// as a reminder, not as legal advice: the product owner's counsel decides what applies.
const NotifyWithin = 72 * time.Hour

// Build assembles the report. dataDir is the control plane's data directory; key is the master key if the
// data is encrypted. aware is when the operator became aware of the incident (zero: not given).
func Build(st *store.Store, dataDir string, key *seal.Key, sc Scenario, from, to, aware, now time.Time) (Report, error) {
	r := Report{Scenario: sc, From: from, To: to, Aware: aware, GeneratedAt: now}
	if !aware.IsZero() {
		r.Deadline = aware.Add(NotifyWithin)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "store.json")); err == nil {
		r.Sealed = seal.IsSealed(b)
	}
	ap := filepath.Join(dataDir, "audit.jsonl")
	if n, err := audit.Verify(ap); err != nil {
		if os.IsNotExist(err) {
			r.AuditOK = "no audit log"
		} else {
			r.AuditOK = "BROKEN: " + err.Error() + ": the log was altered or damaged; treat what it says with care"
		}
	} else {
		r.AuditOK = fmt.Sprintf("intact: %d records, each chained to the one before", n)
	}
	switch sc.Kind {
	case "control-plane", "node", "admin-token":
	default:
		return r, fmt.Errorf("unknown scenario %q (control-plane, node or admin-token)", sc.Kind)
	}
	if sc.Kind == "node" && sc.Node == "" {
		return r, fmt.Errorf("a node scenario needs the node's name")
	}
	if sc.Kind == "admin-token" {
		known := false
		for _, t := range st.Tenants() {
			known = known || t == sc.Tenant
		}
		if !known {
			return r, fmt.Errorf("no tenant %q", sc.Tenant)
		}
	}
	for _, t := range st.Tenants() {
		tr := tenantReport(st, dataDir, t, from, to)
		switch sc.Kind {
		case "control-plane":
			tr.Affected = true
			tr.Why = "the control plane holds every tenant's data; if its disk, a backup or the running server was reached, all of it was within reach" + map[bool]string{true: " (the store and the CA keys are encrypted: the data is exposed only if the master key was also lost)", false: " (the store is NOT encrypted at rest: treat the secrets and the CA keys as exposed)"}[r.Sealed]
		case "admin-token":
			tr.Affected = t == sc.Tenant
			if tr.Affected {
				tr.Why = "an administrator token of this tenant leaked: it can read and change everything this tenant's role allows (see the roles in the README)"
			} else {
				tr.Why = "an administrator token is limited to its own tenant"
			}
		case "node":
			n := nodeRecords(dataDir, t, sc.Node, from, to)
			tr.Affected = n > 0
			if tr.Affected {
				tr.Why = fmt.Sprintf("node %q handled %d decision records of this tenant in the window; a node holds the tenant's inspection key in memory and sees decrypted web traffic while it inspects it", sc.Node, n)
			} else {
				tr.Why = fmt.Sprintf("no decision record of this tenant in the window names node %q (it may still have held the tenant's state if it was enrolled)", sc.Node)
			}
		}
		r.Tenants = append(r.Tenants, tr)
	}
	r.CannotTell = []string{
		"Whether anything was READ. Reads are not recorded: the audit log holds changes made by administrators and the decision records hold access decisions. Assume everything listed under \"data held\" was exposed.",
		"What a person did on a device or inside an app: the platform records who connected to what, not what they did there.",
		"Anything outside this platform: your identity provider, your log system, copies of backups, the nodes' own files and the connectors' and agents' machines.",
		"Whether a copy of an older data directory or backup, from before encryption was turned on, exists with the keys in clear.",
	}
	return r, nil
}

func tenantReport(st *store.Store, dataDir, t string, from, to time.Time) TenantReport {
	cname, cemail, name := st.SecurityContact(t)
	tr := TenantReport{Tenant: t, Name: name, Contact: cemail, ContactName: cname}
	if cemail == "" {
		tr.FallbackTo = st.AlertEmails(t)
	}
	add := func(what string, n int, note string) {
		if n > 0 {
			tr.Categories = append(tr.Categories, Category{what, n, note})
		}
	}
	us, _ := st.Users(t)
	add("people (name, e-mail address, groups)", len(us), "")
	add("provisioned users (SCIM)", len(st.SCIMUserList(t)), "")
	ds, _ := st.Devices(t)
	add("devices (identifier, owner, serial number)", len(ds), "")
	ss, _ := st.Secrets(t)
	add("stored credentials for injection", len(ss), "values held in the store; in clear unless a master key is used")
	es, _ := st.EDMSets(t)
	add("sensitive-data sets (salted hashes only)", len(es), "the original values are not kept")
	if ic, err := st.Inspection(t); err == nil && ic.CACert != "" {
		add("TLS inspection CA and key", 1, "whoever holds the key can read inspected traffic of devices that still trust the CA")
	}
	if cfg := st.SIEM(t); cfg != nil {
		add("log stream destination", 1, "decision records already sent there are outside this platform")
	}
	add("administrator accounts", len(st.Admins(t)), "tokens are stored hashed")
	days, first, last := archiveDays(dataDir, t)
	tr.ArchiveDays, tr.ArchiveFrom, tr.ArchiveTo = days, first, last
	if days > 0 {
		add("decision records (who connected to what, from which device, allowed or not)", days, "counted in days of records on disk, not records; web addresses and app names are in them")
	}
	if ev, err := audit.ReadAll(filepath.Join(dataDir, "audit.jsonl"), t); err == nil {
		tr.AuditActors = map[string]int{}
		for _, e := range ev {
			if !e.TS.Before(from) && e.TS.Before(to) {
				tr.AuditActions++
				tr.AuditActors[e.Actor]++
			}
		}
	}
	return tr
}

func archiveDays(dataDir, tenant string) (n int, first, last string) {
	files, _ := os.ReadDir(filepath.Join(dataDir, "decisions", decisions.TenantDir(tenant)))
	var days []string
	for _, f := range files {
		if d, ok := strings.CutSuffix(f.Name(), ".jsonl"); ok {
			if _, err := time.Parse("2006-01-02", d); err == nil {
				days = append(days, d)
			}
		}
	}
	sort.Strings(days)
	if len(days) == 0 {
		return 0, "", ""
	}
	return len(days), days[0], days[len(days)-1]
}

// nodeRecords counts the tenant's archived decision records in the window that were written by the node.
func nodeRecords(dataDir, tenant, node string, from, to time.Time) int {
	dir := filepath.Join(dataDir, "decisions", decisions.TenantDir(tenant))
	files, _ := os.ReadDir(dir)
	needle := `"en":"` + node + `"`
	n := 0
	for _, f := range files {
		d, ok := strings.CutSuffix(f.Name(), ".jsonl")
		if !ok {
			continue
		}
		day, err := time.Parse("2006-01-02", d)
		if err != nil || day.Add(24*time.Hour).Before(from) || day.After(to) {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			if strings.Contains(sc.Text(), needle) {
				n++
			}
		}
		fh.Close()
	}
	return n
}

// Text renders the report for a person to work from.
func (r Report) Text() string {
	var b strings.Builder
	f := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	f("INCIDENT SCOPE REPORT (made %s)", r.GeneratedAt.UTC().Format(time.RFC3339))
	f("Scenario: %s%s%s", r.Scenario.Kind, map[bool]string{true: " " + r.Scenario.Node, false: ""}[r.Scenario.Node != ""], map[bool]string{true: " of tenant " + r.Scenario.Tenant, false: ""}[r.Scenario.Tenant != ""])
	f("Window: %s to %s", r.From.UTC().Format("2 Jan 2006 15:04"), r.To.UTC().Format("2 Jan 2006 15:04"))
	if !r.Aware.IsZero() {
		f("Aware since %s. If this is a personal-data breach, the supervisory authority is to be told within 72 hours of becoming aware: by %s.", r.Aware.UTC().Format("2 Jan 2006 15:04 MST"), r.Deadline.UTC().Format("2 Jan 2006 15:04 MST"))
		f("(This is a reminder, not legal advice: whether it is a notifiable breach, and who must be told, is for your counsel.)")
	} else {
		f("No \"aware\" time given: write down when you became aware, because the 72-hour period runs from then (-aware).")
	}
	f("Store encrypted at rest: %v. Audit chain: %s.", r.Sealed, r.AuditOK)
	f("")
	affected := 0
	for _, t := range r.Tenants {
		if t.Affected {
			affected++
		}
	}
	f("%d of %d tenants are in scope.", affected, len(r.Tenants))
	for _, t := range r.Tenants {
		f("")
		mark := "not in scope"
		if t.Affected {
			mark = "IN SCOPE"
		}
		f("== %s (%s): %s", t.Tenant, t.Name, mark)
		f("   %s", t.Why)
		switch {
		case t.Contact != "":
			f("   Tell: %s <%s>", t.ContactName, t.Contact)
		case len(t.FallbackTo) > 0:
			f("   No security contact set. Alert recipients: %s", strings.Join(t.FallbackTo, ", "))
		default:
			f("   NO CONTACT: no security contact and no alert recipients. Find another way to reach this tenant.")
		}
		if t.Affected {
			f("   Data held:")
			for _, c := range t.Categories {
				line := fmt.Sprintf("     - %s: %d", c.What, c.Count)
				if c.Note != "" {
					line += " (" + c.Note + ")"
				}
				f("%s", line)
			}
			if t.ArchiveDays > 0 {
				f("   Decision records on disk: %d days, %s to %s", t.ArchiveDays, t.ArchiveFrom, t.ArchiveTo)
			}
			f("   Administrator actions in the window: %d", t.AuditActions)
			var actors []string
			for a, n := range t.AuditActors {
				actors = append(actors, fmt.Sprintf("%s (%d)", a, n))
			}
			sort.Strings(actors)
			if len(actors) > 0 {
				f("     by: %s", strings.Join(actors, ", "))
			}
		}
	}
	f("")
	f("What this report cannot tell you:")
	for _, c := range r.CannotTell {
		f("  - %s", c)
	}
	return b.String()
}
