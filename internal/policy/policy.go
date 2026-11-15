// Package policy implements the SMB-ZTX rule model and evaluator (DESIGN.md D2).
package policy

import (
	"encoding/json"
	"fmt"
	"github.com/larytet/zscaler/internal/filetype"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RestrictedGroup is a product-side group. An admin can put a user in it at any
// time without waiting for the identity provider; the safe-defaults policy denies it first.
const RestrictedGroup = "restricted"

type Kind string

const (
	Private Kind = "private"
	Web     Kind = "web"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
	Warn  Action = "warn"
	// Approve means: allow only while an admin-approved, time-limited grant exists
	// for this user and app (just-in-time access). Private policies only.
	Approve Action = "require_approval"
	// Isolate means: allow only when the request comes from the workspace browser
	// (requirements v0.6). From anywhere else it is denied with reason workspace-required.
	Isolate Action = "isolate"
)

// Posture is a device posture report that has already been signature-verified.
// Tri-state values are pointers: nil means unknown and is treated as false.
type Posture struct {
	OS             string    `json:"os"`
	OSVersion      string    `json:"os_version"`
	DiskEncrypted  *bool     `json:"disk_encrypted"`
	FirewallOn     *bool     `json:"firewall_on"`
	ScreenLock     *bool     `json:"screen_lock"`
	RemovableMedia *bool     `json:"removable_media"` // true: a removable drive is mounted
	ReportedAt     time.Time `json:"ts"`
}

type User struct {
	Subject  string
	Email    string
	Groups   []string
	Disabled bool
	// Operator is the person an AI agent runs for ("agent:" identities only). An agent can reach
	// nothing its operator cannot (AGS-004).
	Operator string
	// Risk is a 0 to 100 score computed by the control plane (0 when unknown).
	Risk int
}

type Device struct {
	ID      string
	Revoked bool
	Posture *Posture // nil: no report
}

type Request struct {
	Kind       Kind
	User       User
	Device     Device
	App        string   // segment ID (private)
	Host       string   // web
	Categories []string // web, from classification
	SrcIP      netip.Addr
	Now        time.Time
	// Set only for inspected web requests.
	// Workspace is true when the connection used a workspace certificate.
	Workspace bool
	Inspected bool
	Path      string
	Method    string
	DLPHits   []string // data types found in the request body
	// ResponseDLPHits is set only for the second evaluation, made once the response is known.
	ResponseDLPHits []string
	ResponsePhase   bool
	// UploadFiles are the kinds of file the decrypted request carries; DownloadFiles, in the response
	// phase, the kinds the response carries (package filetype).
	UploadFiles   []string
	DownloadFiles []string
	// CloudApps are the apps the request's host belongs to; CloudActions the "app:action" pairs the
	// (decrypted or plain) request is recognised as (package cloudapps).
	CloudApps    []string
	CloudActions []string
	// AssumeDevice skips the checks that belong to a device (network, workspace, posture). Used when
	// asking whether a person could reach something, without having one of their devices at hand.
	AssumeDevice bool
}

type Decision struct {
	Action  Action
	RuleID  string // "" means default
	Reason  string
	Capture bool   // the deciding rule asks for the exchange to be captured
	Inject  string // the deciding rule asks for this secret to be added to the request
}

type PostureMatch struct {
	MinOS         map[string]string `json:"min_os,omitempty"`
	DiskEncrypted *bool             `json:"disk_encrypted,omitempty"`
	FirewallOn    *bool             `json:"firewall_on,omitempty"`
	ScreenLock    *bool             `json:"screen_lock,omitempty"`
	// RemovableMedia false requires that no removable drive is mounted; true requires one. Unknown fails.
	RemovableMedia *bool `json:"removable_media,omitempty"`
	MaxAgeSeconds  int   `json:"max_age_seconds,omitempty"`
}

type TimeMatch struct {
	Days []string `json:"days,omitempty"`
	From string   `json:"from,omitempty"` // HH:MM inclusive
	To   string   `json:"to,omitempty"`   // HH:MM exclusive
	TZ   string   `json:"tz,omitempty"`
}

type NetworkMatch struct {
	SrcCIDRs []string `json:"src_cidrs,omitempty"`
}

type Match struct {
	Users      []string      `json:"users,omitempty"`
	Groups     []string      `json:"groups,omitempty"`
	Apps       []string      `json:"apps,omitempty"`
	Domains    []string      `json:"domains,omitempty"`
	Categories []string      `json:"categories,omitempty"`
	Posture    *PostureMatch `json:"posture,omitempty"`
	Time       *TimeMatch    `json:"time,omitempty"`
	Network    *NetworkMatch `json:"network,omitempty"`
	// Paths (URL path prefixes) and Methods apply only to inspected (decrypted) web
	// traffic. On traffic that is not inspected a rule that names them never matches.
	// Workspace is true to match only requests from the workspace browser, false for only
	// requests from anywhere else. Unset matches both.
	Workspace *bool    `json:"workspace,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	// DLP names data types (see package dlp). The rule matches when the decrypted request
	// body contains any of them. Inspected web traffic only.
	DLP []string `json:"dlp,omitempty"`
	// DLPResponse names data types to look for in the RESPONSE body (for example an AI tool
	// answering with a customer's card number). Inspected web traffic only; the proxy applies
	// the rule after the origin has answered and before anything reaches the user.
	DLPResponse []string `json:"dlp_response,omitempty"`
	// UploadFileTypes and DownloadFileTypes name kinds of file (see package filetype: "executable",
	// "archive", "disguised", "ext:.iso", ...). The rule matches when a decrypted upload, or a
	// download, carries one of them, by name, declared type or file signature (ZIA-013). Web rules
	// with the action deny; inspected traffic only.
	UploadFileTypes   []string `json:"upload_file_types,omitempty"`
	DownloadFileTypes []string `json:"download_file_types,omitempty"`
	// CloudApps names apps of the catalogue (package cloudapps), such as "dropbox". With no CloudActions the
	// rule matches any request to the app's domains; with CloudActions ("upload", "post", "share", ...)
	// it matches requests recognised as one of those actions of one of the apps, which needs decrypted
	// traffic. Web rules only (ZIA-011).
	CloudApps    []string `json:"cloud_apps,omitempty"`
	CloudActions []string `json:"cloud_actions,omitempty"`
	// MaxRisk and MinRisk bound the user's risk score (inclusive).
	MaxRisk *int `json:"max_risk,omitempty"`
	MinRisk *int `json:"min_risk,omitempty"`
}

type Rule struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Action   Action `json:"action"`
	Match    Match  `json:"match"`
	Reason   string `json:"reason,omitempty"`
	// Capture keeps the decrypted exchange of every request this rule decides, for forensics
	// (ZIA-022b). Web rules only, and only on inspected traffic. It is an explicit, audited choice.
	Capture bool `json:"capture,omitempty"`
	// Inject names a stored secret that the proxy adds to the request, after this rule allows it,
	// so the caller (an AI agent) never holds the credential (AGS-001). Web allow rules only.
	Inject string `json:"inject,omitempty"`
}

type Policy struct {
	Kind          Kind   `json:"kind"`
	Version       int    `json:"version"`
	DefaultAction Action `json:"default_action"`
	Rules         []Rule `json:"rules"`

	compiled []compiledRule
	idx      index
}

// index narrows the rules worth checking for a request. Matching still runs
// the full check on each candidate, so the result equals a linear scan.
type index struct {
	anyWho  []int            // rules with no users or groups
	byGroup map[string][]int // rule positions by group
	byUser  map[string][]int // rule positions by lower-cased email or subject
}

type compiledRule struct {
	Rule
	users, groups, apps, cats map[string]bool
	domains                   []string
	cidrs                     []netip.Prefix
	loc                       *time.Location
	from, to                  int // minutes, -1 if unset
	days                      map[time.Weekday]bool
}

// Parse decodes and compiles a policy; it validates first.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy json: %w", err)
	}
	return &p, p.Compile(nil)
}

// Compile validates and prepares the policy. known is the set of valid
// segment IDs; nil skips the reference check.
func (p *Policy) Compile(known map[string]bool) error {
	if errs := Validate(p, known); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return fmt.Errorf("invalid policy: %s", strings.Join(msgs, "; "))
	}
	rules := append([]Rule(nil), p.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	p.compiled = p.compiled[:0]
	for _, r := range rules {
		c := compiledRule{Rule: r, from: -1, to: -1}
		c.users, c.groups = set(r.Match.Users), set(r.Match.Groups)
		c.apps, c.cats = set(r.Match.Apps), set(r.Match.Categories)
		for _, d := range r.Match.Domains {
			c.domains = append(c.domains, normHost(d))
		}
		if n := r.Match.Network; n != nil {
			for _, s := range n.SrcCIDRs {
				pf, _ := netip.ParsePrefix(s)
				c.cidrs = append(c.cidrs, pf)
			}
		}
		if t := r.Match.Time; t != nil {
			c.loc = time.UTC
			if t.TZ != "" {
				c.loc, _ = time.LoadLocation(t.TZ)
			}
			if t.From != "" {
				c.from, _ = parseHM(t.From)
				c.to, _ = parseHM(t.To)
			}
			if len(t.Days) > 0 {
				c.days = map[time.Weekday]bool{}
				for _, d := range t.Days {
					c.days[dayNames[strings.ToLower(d)]] = true
				}
			}
		}
		p.compiled = append(p.compiled, c)
	}
	p.idx = index{byGroup: map[string][]int{}, byUser: map[string][]int{}}
	for i, c := range p.compiled {
		if len(c.Match.Users)+len(c.Match.Groups) == 0 {
			p.idx.anyWho = append(p.idx.anyWho, i)
			continue
		}
		for _, g := range c.Match.Groups {
			p.idx.byGroup[g] = append(p.idx.byGroup[g], i)
		}
		for _, u := range c.Match.Users {
			p.idx.byUser[strings.ToLower(u)] = append(p.idx.byUser[strings.ToLower(u)], i)
		}
	}
	return nil
}

// Evaluate is pure and total: it never panics and always returns a decision.
func (p *Policy) Evaluate(r Request) (d Decision) {
	defer func() {
		if rec := recover(); rec != nil {
			d = Decision{Action: Deny, Reason: "evaluation-error"}
		}
	}()
	if p == nil || p.compiled == nil && len(p.Rules) > 0 {
		return Decision{Action: Deny, Reason: "evaluation-error"}
	}
	if r.User.Disabled {
		return Decision{Action: Deny, Reason: "user-disabled"}
	}
	if r.Device.Revoked {
		return Decision{Action: Deny, Reason: "device-revoked"}
	}
	r.User.Email = strings.ToLower(r.User.Email) // once, not per rule
	var buf [16]int
	cand := append(buf[:0], p.idx.anyWho...)
	for _, g := range r.User.Groups {
		cand = append(cand, p.idx.byGroup[g]...)
	}
	cand = append(cand, p.idx.byUser[r.User.Email]...)
	if r.User.Subject != "" {
		cand = append(cand, p.idx.byUser[strings.ToLower(r.User.Subject)]...)
	}
	sort.Ints(cand) // priority order; duplicates are harmless (same rule, same answer)
	for _, i := range cand {
		c := &p.compiled[i]
		if c.matches(p.Kind, r) {
			if c.Action == Isolate { // allowed only inside the workspace
				if r.Workspace {
					return Decision{Action: Allow, RuleID: c.ID, Reason: "workspace"}
				}
				return Decision{Action: Deny, RuleID: c.ID, Reason: "workspace-required"}
			}
			return Decision{Action: c.Action, RuleID: c.ID, Reason: c.Reason, Capture: c.Capture, Inject: c.Inject}
		}
	}
	def := p.DefaultAction
	if p.Kind == Private || def == "" {
		def = Deny
	}
	return Decision{Action: def, Reason: "default"}
}

func (c *compiledRule) matches(kind Kind, r Request) bool {
	m := c.Match
	if len(c.users)+len(c.groups) > 0 {
		ok := c.users[r.User.Email] || c.users[r.User.Subject]
		for _, g := range r.User.Groups {
			if c.groups[g] {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if kind == Private {
		if len(c.apps) > 0 && !c.apps[r.App] {
			return false
		}
	} else {
		if len(c.domains) > 0 && !hostMatches(c.domains, r.Host) {
			return false
		}
		if len(c.cats) > 0 {
			ok := false
			for _, cat := range r.Categories {
				if c.cats[cat] {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
	}
	if len(c.cidrs) > 0 && !r.AssumeDevice {
		ok := false
		for _, pf := range c.cidrs {
			if r.SrcIP.IsValid() && pf.Contains(r.SrcIP.Unmap()) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if m.Workspace != nil && !r.AssumeDevice && *m.Workspace != r.Workspace {
		return false
	}
	if len(m.DLPResponse) > 0 { // a response rule matches only in the response phase, on what the response held
		if !r.ResponsePhase {
			return false
		}
		ok := false
		for _, want := range m.DLPResponse {
			for _, got := range r.ResponseDLPHits {
				if want == got {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.CloudApps) > 0 {
		ok := false
		for _, app := range m.CloudApps {
			if len(m.CloudActions) == 0 {
				ok = ok || contains(r.CloudApps, app)
				continue
			}
			for _, act := range m.CloudActions {
				ok = ok || contains(r.CloudActions, app+":"+act)
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.UploadFileTypes) > 0 { // a request rule: the upload is seen only when decrypted
		if r.ResponsePhase || !r.Inspected || !filetype.Match(m.UploadFileTypes, r.UploadFiles) {
			return false
		}
	}
	if len(m.DownloadFileTypes) > 0 { // a response rule, applied once the response is known
		if !r.ResponsePhase || !filetype.Match(m.DownloadFileTypes, r.DownloadFiles) {
			return false
		}
	}
	if len(m.DLP) > 0 {
		ok := false
		for _, want := range m.DLP {
			for _, got := range r.DLPHits {
				if want == got {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.Paths)+len(m.Methods) > 0 {
		if !r.Inspected {
			return false
		}
		if len(m.Paths) > 0 {
			ok := false
			for _, p := range m.Paths {
				if strings.HasPrefix(r.Path, p) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		if len(m.Methods) > 0 {
			ok := false
			for _, mm := range m.Methods {
				if strings.EqualFold(mm, r.Method) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
	}
	if (m.MaxRisk != nil && r.User.Risk > *m.MaxRisk) || (m.MinRisk != nil && r.User.Risk < *m.MinRisk) {
		return false
	}
	if m.Time != nil && !c.timeOK(r.Now) {
		return false
	}
	if m.Posture != nil && !r.AssumeDevice && !postureOK(m.Posture, r.Device.Posture, r.Now) {
		return false
	}
	return true
}

func (c *compiledRule) timeOK(now time.Time) bool {
	t := now.In(c.loc)
	if c.days != nil && !c.days[t.Weekday()] {
		return false
	}
	if c.from >= 0 {
		mins := t.Hour()*60 + t.Minute()
		if c.from <= c.to {
			return mins >= c.from && mins < c.to
		}
		return mins >= c.from || mins < c.to // overnight window
	}
	return true
}

func postureOK(req *PostureMatch, got *Posture, now time.Time) bool {
	if got == nil {
		return false // fail closed
	}
	if req.MaxAgeSeconds > 0 {
		age := now.Sub(got.ReportedAt)
		if age < 0 || age > time.Duration(req.MaxAgeSeconds)*time.Second {
			return false
		}
	}
	for _, c := range []struct{ want, have *bool }{
		{req.DiskEncrypted, got.DiskEncrypted},
		{req.FirewallOn, got.FirewallOn},
		{req.ScreenLock, got.ScreenLock},
		{req.RemovableMedia, got.RemovableMedia},
	} {
		if c.want != nil && (c.have == nil || *c.have != *c.want) {
			return false
		}
	}
	if len(req.MinOS) > 0 {
		min, ok := req.MinOS[strings.ToLower(got.OS)]
		if !ok || CompareVersions(got.OSVersion, min) < 0 {
			return false
		}
	}
	return true
}

// CompareVersions compares dotted numeric versions. Non-numeric parts count as 0.
func CompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return h
}

// NormalizeHost is exported for the web proxy and classifier.
func NormalizeHost(h string) string { return normHost(h) }

func hostMatches(domains []string, host string) bool {
	host = normHost(host)
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
		m[strings.ToLower(x)] = true
	}
	return m
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func parseHM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

// UsesUploadFileTypes reports whether any rule needs uploads checked for file type.
func (p *Policy) UsesUploadFileTypes() bool {
	for _, r := range p.Rules {
		if len(r.Match.UploadFileTypes) > 0 {
			return true
		}
	}
	return false
}

// UsesDownloadFileTypes reports whether any rule needs downloads checked for file type.
func (p *Policy) UsesDownloadFileTypes() bool {
	for _, r := range p.Rules {
		if len(r.Match.DownloadFileTypes) > 0 {
			return true
		}
	}
	return false
}

// UsesDLP reports whether any rule needs the request body scanned, so the proxy only
// pays for scanning when a policy asks for it.
func (p *Policy) UsesDLP() bool {
	for _, r := range p.Rules {
		if len(r.Match.DLP) > 0 {
			return true
		}
	}
	return false
}

// EvaluateResponse decides, once the origin has answered, whether the response may reach the
// user. Only rules with a dlp_response condition take part; every other rule was already
// applied to the request. No matching rule means allow.
func (p *Policy) EvaluateResponse(r Request) (d Decision) {
	defer func() {
		if rec := recover(); rec != nil {
			d = Decision{Action: Deny, Reason: "evaluation-error"}
		}
	}()
	r.ResponsePhase = true
	for i := range p.compiled {
		c := &p.compiled[i]
		if (len(c.Match.DLPResponse) > 0 || len(c.Match.DownloadFileTypes) > 0) && c.matches(p.Kind, r) {
			return Decision{Action: c.Action, RuleID: c.ID, Reason: c.Reason}
		}
	}
	return Decision{Action: Allow, Reason: "default"}
}

// UsesResponseDLP reports whether any rule needs response bodies scanned.
func (p *Policy) UsesResponseDLP() bool {
	for _, r := range p.Rules {
		if len(r.Match.DLPResponse) > 0 {
			return true
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
