package evidence

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/policy"
)

func tr() *bool { b := true; return &b }

func find(r Report, prefix string) Item {
	for _, it := range r.Items {
		if strings.HasPrefix(it.Control, prefix) {
			return it
		}
	}
	return Item{}
}

func good() Inputs {
	return Inputs{Now: time.Now(), Segments: 3, IDPConfigured: true, Devices: 5, Users: 4, Admins: 1, Viewers: 1,
		Decisions30d: 200, AuditRecords: 12,
		Private: &policy.Policy{Kind: policy.Private, DefaultAction: policy.Deny, Rules: []policy.Rule{
			{ID: "a", Priority: 1, Action: policy.Allow, Match: policy.Match{Groups: []string{"g"}, Posture: &policy.PostureMatch{DiskEncrypted: tr()}}}}},
		Web: &policy.Policy{Kind: policy.Web, Rules: []policy.Rule{{ID: "w", Priority: 1, Action: policy.Deny}}}}
}

func TestEvidencedWhenConfigured(t *testing.T) {
	r := Build(good())
	for _, c := range []string{"Network segmentation", "Device health checks", "Web filtering", "Logging and tamper-evident", "Prompt removal", "Separation of administrative", "Encryption of data in transit"} {
		if it := find(r, c); it.Status != Evidenced {
			t.Errorf("%s: %q %s", c, it.Status, it.Detail)
		}
	}
	if it := find(r, "Access logging"); it.Status != Partial || !strings.Contains(it.Detail, "confirm your retention") {
		t.Errorf("access logging must be partial and say why: %+v", it)
	}
}

func TestNeverClaimsWhatItCannotSee(t *testing.T) { // the point of the report
	r := Build(good())
	for _, c := range []string{"Multi-factor authentication", "Endpoint detection", "Backups"} {
		if it := find(r, c); it.Status != NotEvidenced {
			t.Errorf("%s must be 'not evidenced', got %q", c, it.Status)
		}
	}
	if !strings.Contains(r.Disclaimer, "not an audit") {
		t.Error("disclaimer missing")
	}
}

func TestMissingConfigurationIsReported(t *testing.T) {
	in := good()
	in.Segments, in.Private, in.Web, in.Decisions30d, in.AuditRecords = 0, nil, nil, 0, 0
	r := Build(in)
	for _, c := range []string{"Network segmentation", "Device health checks", "Web filtering", "Access logging"} {
		if it := find(r, c); it.Status != NotEvidenced {
			t.Errorf("%s: %q", c, it.Status)
		}
	}
	if it := find(r, "Logging and tamper-evident"); it.Status != Partial {
		t.Errorf("empty audit log: %q", it.Status)
	}
}

func TestPolicyWithoutPostureIsNotEvidenced(t *testing.T) {
	in := good()
	in.Private.Rules[0].Match.Posture = nil
	if it := find(Build(in), "Device health checks"); it.Status != NotEvidenced {
		t.Fatalf("%q", it.Status)
	}
}

func TestBrokenAuditChainIsNotHidden(t *testing.T) {
	in := good()
	in.AuditErr = errors.New("record 4: content altered")
	it := find(Build(in), "Logging and tamper-evident")
	if it.Status != NotEvidenced || !strings.Contains(it.Detail, "content altered") {
		t.Fatalf("%+v", it)
	}
}

func TestOpenPostureFailuresAreMentionedAndTextRenders(t *testing.T) {
	in := good()
	in.OpenPostureFail = 2
	r := Build(in)
	if !strings.Contains(find(r, "Device health checks").Detail, "2 device(s) currently fail") {
		t.Fatal("open posture failures not reported")
	}
	txt := r.Text()
	if !strings.Contains(txt, "Status: not evidenced by this product") || !strings.Contains(txt, "Multi-factor authentication") {
		t.Fatal(txt)
	}
}
