// Package evidence assembles answers to common cyber-insurance questions from
// what this product actually knows. It never claims a control it cannot see:
// MFA and endpoint protection live in other systems and are marked as such.
package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

type Status string

const (
	Evidenced    Status = "evidenced"
	Partial      Status = "partial"
	NotEvidenced Status = "not evidenced by this product"
)

type Item struct {
	Control string `json:"control"`
	Status  Status `json:"status"`
	Detail  string `json:"detail"`
}

type Inputs struct {
	Now             time.Time
	Segments        int
	Private, Web    *policy.Policy
	Devices         int
	RevokedDevices  int
	Users           int
	DisabledUsers   int
	OpenPostureFail int
	Decisions30d    int
	AuditRecords    int
	AuditErr        error
	Admins, Viewers int
	IDPConfigured   bool
}

type Report struct {
	Generated  time.Time `json:"generated"`
	Items      []Item    `json:"items"`
	Disclaimer string    `json:"disclaimer"`
}

func Build(in Inputs) Report {
	r := Report{Generated: in.Now, Disclaimer: "This report states what this product can show about its own configuration and activity. It is not an audit or a certification. Verify every answer before submitting it to an insurer, and answer the items marked 'not evidenced' from the systems that own them."}
	add := func(c string, s Status, d string) { r.Items = append(r.Items, Item{c, s, d}) }

	// segmentation and least privilege
	switch {
	case in.Private == nil || in.Segments == 0:
		add("Network segmentation / least-privilege access to internal systems", NotEvidenced, "No private-access segments or no private policy are configured.")
	default:
		rules := len(in.Private.Rules)
		add("Network segmentation / least-privilege access to internal systems", Evidenced,
			fmt.Sprintf("%d application segments; private-access policy is default-deny with %d allow/deny rules (the product refuses any other default). Apps are not reachable except through the broker.", in.Segments, rules))
	}
	// device posture
	if in.Private != nil && requiresPosture(in.Private) {
		d := "Access rules require device posture (disk encryption and/or firewall) checked every 5 minutes; a missing or stale report is treated as failing."
		if in.OpenPostureFail > 0 {
			d += fmt.Sprintf(" %d device(s) currently fail the baseline.", in.OpenPostureFail)
		}
		add("Device health checks before access (encryption, firewall)", Evidenced, d)
	} else {
		add("Device health checks before access (encryption, firewall)", NotEvidenced, "No access rule requires device posture.")
	}
	// web filtering
	if in.Web != nil && len(in.Web.Rules) > 0 {
		add("Web filtering / malicious-site blocking", Evidenced, fmt.Sprintf("Web policy with %d rules (categories and domains). Host-name based: web content is not inspected.", len(in.Web.Rules)))
	} else {
		add("Web filtering / malicious-site blocking", NotEvidenced, "No web policy is configured.")
	}
	// logging
	switch {
	case in.AuditErr != nil:
		add("Logging and tamper-evident audit trail of administrative changes", NotEvidenced, "The audit log failed verification: "+in.AuditErr.Error())
	case in.AuditRecords > 0:
		add("Logging and tamper-evident audit trail of administrative changes", Evidenced, fmt.Sprintf("%d admin actions recorded in a hash-chained log; the chain verified intact at report time.", in.AuditRecords))
	default:
		add("Logging and tamper-evident audit trail of administrative changes", Partial, "The audit log is empty.")
	}
	if in.Decisions30d > 0 {
		add("Access logging (who accessed what, allowed or blocked)", Partial, fmt.Sprintf("%d access decisions recorded in the last 30 days. Retention is a bounded in-memory history on the control plane plus a file on each enforcement node: confirm your retention period against the insurer's requirement.", in.Decisions30d))
	} else {
		add("Access logging (who accessed what, allowed or blocked)", NotEvidenced, "No access decisions were recorded in the last 30 days.")
	}
	// offboarding
	add("Prompt removal of access for leavers and lost devices", Evidenced,
		fmt.Sprintf("Disabling a user or revoking a device ends live sessions within seconds and blocks new ones (%d users disabled, %d devices revoked to date). Device certificates also expire after 12 hours.", in.DisabledUsers, in.RevokedDevices))
	// admin access
	add("Separation of administrative roles", Evidenced, fmt.Sprintf("%d admin and %d read-only accounts. Admin tokens are stored hashed.", in.Admins, in.Viewers))
	// encryption in transit
	add("Encryption of data in transit", Evidenced, "All traffic between agents, enforcement nodes, connectors and the control plane uses mutual TLS 1.3 (device-bound short-lived certificates). Traffic to the open internet is not decrypted or re-encrypted by this product.")
	// identity
	if in.IDPConfigured {
		add("Multi-factor authentication for staff", NotEvidenced, "Sign-in is delegated to your identity provider. Whether it enforces MFA must be confirmed there; this product cannot see it.")
	} else {
		add("Multi-factor authentication for staff", NotEvidenced, "No identity provider is configured.")
	}
	add("Endpoint detection and response / anti-malware on devices", NotEvidenced, "This product checks disk encryption and the firewall only. It does not manage or verify EDR.")
	add("Backups and recovery", NotEvidenced, "Out of scope for this product.")
	return r
}

func requiresPosture(p *policy.Policy) bool {
	for _, r := range p.Rules {
		if r.Action == policy.Allow && r.Match.Posture != nil {
			return true
		}
	}
	return false
}

// Text renders the report for pasting into a questionnaire.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security controls evidence, generated %s\r\n\r\n%s\r\n", r.Generated.Format("2 Jan 2006 15:04 MST"), r.Disclaimer)
	for _, it := range r.Items {
		fmt.Fprintf(&b, "\r\n%s\r\n  Status: %s\r\n  %s\r\n", it.Control, it.Status, it.Detail)
	}
	return b.String()
}
