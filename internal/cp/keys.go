package cp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/larytet/zscaler/internal/store"
)

// Rotation of the keys and tokens, and one place that says how old each is (GAP-REQ-05).

const (
	oldTokenAfter = 180 * 24 * time.Hour // an administrator token this old is listed as worth replacing
	caWarnDays    = 180                  // a CA with fewer days left is warned about
)

func (a *API) rotateAdminToken(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.rotateToken(c, r.PathValue("name"))
}

// rotateOwnToken lets anyone who is signed in replace their own token, for example after it may have been seen.
func (a *API) rotateOwnToken(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.rotateToken(c, c.actor)
}

func (a *API) rotateToken(c ctxInfo, name string) (any, error) {
	tok, err := a.Store.RotateAdmin(c.tenant, name)
	if err != nil {
		return nil, err
	}
	a.log(c, "admin.rotate", name, nil, nil) // the token itself is never logged
	return map[string]any{"name": name, "token": tok, "note": "The old token no longer works. This one is shown once."}, nil
}

// rotateInspection replaces the TLS inspection CA and leaf key. With inspection on, devices that do not yet
// trust the new certificate would see certificate errors on inspected sites, so it needs {"now": true},
// or inspection turned off first.
func (a *API) rotateInspection(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in struct {
		Now bool `json:"now"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) { // no body at all is fine
		return nil, fail(400, "bad_json", err.Error())
	}
	cfg, err := a.Store.Inspection(c.tenant)
	if err != nil {
		return nil, err
	}
	if cfg.CACert == "" {
		return nil, fail(404, "not_found", "inspection has never been turned on, so there is no CA to replace")
	}
	if cfg.Enabled && !in.Now {
		return nil, fail(409, "inspection_on", "inspection is on: devices that do not yet trust the new certificate would show certificate errors on every inspected site. Turn inspection off first (PUT /v1/inspection), rotate, install the new certificate (GET /v1/inspection/ca.pem) on the devices, then turn it on; or send {\"now\": true} to rotate at once and accept the errors until devices have it")
	}
	oldFP, newFP, err := a.Store.RotateInspection(c.tenant)
	if err != nil {
		return nil, err
	}
	a.log(c, "inspection.rotate", "ca", map[string]string{"fingerprint": oldFP}, map[string]string{"fingerprint": newFP})
	return map[string]any{
		"old_fingerprint": oldFP, "new_fingerprint": newFP, "inspection_on": cfg.Enabled,
		"next": "Install the new certificate (GET /v1/inspection/ca.pem) on every device and remove the old one (fingerprint above). Until a device trusts the new one, inspected HTTPS sites show certificate errors there. Workspace browsers pick up the new key the next time they start. If the old key may have leaked, anything it signed is trusted by devices that still hold the old certificate until you remove it.",
	}, nil
}

type keyItem struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	DaysLeft    *int   `json:"days_left,omitempty"`
	Changed     string `json:"last_replaced,omitempty"`
	Rotation    string `json:"how_to_replace"`
}

func daysLeft(t time.Time, now time.Time) *int {
	d := int(t.Sub(now).Hours() / 24)
	return &d
}

// keyStatus says what keys and long-lived tokens the platform holds, how old they are and how to replace
// each, and warns about a CA close to its end, a missing master key and old administrator tokens.
func (a *API) keyStatus(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	now := a.Store.Time()
	var items []keyItem
	var warn []string
	if a.RootCACert != nil {
		h := sha256.Sum256(a.RootCACert.Raw)
		it := keyItem{Name: "device certificate authority (root)", Fingerprint: hex.EncodeToString(h[:]), NotAfter: a.RootCACert.NotAfter.UTC().Format(time.RFC3339), DaysLeft: daysLeft(a.RootCACert.NotAfter, now),
			Rotation: "not built: replacing it means making a new data directory and enrolling every enforcement node, connector and agent again (see README, 'If a key leaked')"}
		items = append(items, it)
		if *it.DaysLeft < caWarnDays {
			warn = append(warn, "The device certificate authority expires in under 180 days; plan the re-enrolment now, because there is no overlap period.")
		}
	}
	if a.PolicyPub != nil {
		der, _ := x509.MarshalPKIXPublicKey(a.PolicyPub)
		h := sha256.Sum256(der)
		items = append(items, keyItem{Name: "policy signing key", Fingerprint: hex.EncodeToString(h[:]), Rotation: "not built: enforcement nodes pin its public key when they enrol, so replacing it means enrolling every node again"})
	}
	if cfg, err := a.Store.Inspection(c.tenant); err == nil && cfg.CACert != "" {
		it := keyItem{Name: "TLS inspection CA", Fingerprint: store.Fingerprint(cfg.CACert), Rotation: "POST /v1/inspection/rotate"}
		if !cfg.Rotated.IsZero() {
			it.Changed = cfg.Rotated.UTC().Format(time.RFC3339)
		}
		items = append(items, it)
	}
	ads := a.Store.Admins(c.tenant)
	var old []string
	for _, ad := range ads {
		since := ad.Created
		if !ad.Rotated.IsZero() {
			since = ad.Rotated
		}
		if !since.IsZero() && now.Sub(since) > oldTokenAfter && ad.Expires.IsZero() {
			old = append(old, ad.Name)
		}
	}
	sort.Strings(old)
	if len(old) > 0 {
		warn = append(warn, "Administrator tokens that have never been replaced in over 180 days: replace them with POST /v1/admins/{name}/rotate.")
	}
	if !a.AtRestSealed {
		warn = append(warn, "The CA key, the signing key and the store are stored in clear on this server. Start the control plane with a master key (-master-key-file).")
	}
	if warn == nil {
		warn = []string{}
	}
	if old == nil {
		old = []string{}
	}
	return map[string]any{
		"keys":                        items,
		"master_key_in_use":           a.AtRestSealed,
		"admin_tokens":                map[string]any{"count": len(ads), "not_replaced_in_180_days": old, "how_to_replace": "POST /v1/admins/{name}/rotate (an owner), or POST /v1/me/rotate for your own"},
		"scim_token_how_to_replace":   "POST /v1/scim/token (the old token stops working at once)",
		"master_key_how_to_replace":   "ztx-cp rekey -data D -master-key-file OLD -new-master-key-file NEW (stop the control plane first)",
		"device_certificate_lifetime": "set by -device-cert-ttl (default 12 hours); devices renew on their own",
		"warnings":                    warn,
	}, nil
}
