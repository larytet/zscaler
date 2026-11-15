package devhealth

import (
	"github.com/larytet/zscaler/internal/pathprobe"
	"strings"
	"testing"
	"time"
)

func ip(n int) *int { return &n }

func TestParseMeminfo(t *testing.T) {
	text := "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\nBuffers: 5 kB\n"
	total, avail, ok := ParseMeminfo(text)
	if !ok || total != 16000000 || avail != 4000000 {
		t.Fatalf("%d %d %v", total, avail, ok)
	}
	for _, bad := range []string{"", "MemTotal: x kB\nMemAvailable: 1 kB", "MemTotal: 5 kB\n", "garbage"} {
		if _, _, ok := ParseMeminfo(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCollectNeverClaimsMoreThanItKnows(t *testing.T) {
	s := Collect() // on Linux CI everything is known; elsewhere fields may be nil, which is fine
	for name, v := range map[string]*int{"cpu": s.CPULoadPct, "mem": s.MemUsedPct, "disk": s.DiskUsedPct} {
		if v != nil && (*v < 0 || *v > 999) {
			t.Errorf("%s out of range: %d", name, *v)
		}
	}
	if s.MemUsedPct != nil && *s.MemUsedPct > 100 {
		t.Errorf("memory over 100 percent: %d", *s.MemUsedPct)
	}
	if s.DiskUsedPct != nil && *s.DiskUsedPct > 100 {
		t.Errorf("disk over 100 percent: %d", *s.DiskUsedPct)
	}
}

func TestFindingsThresholdsAndWording(t *testing.T) {
	ok := Entry{User: "alice", Device: "d1", Snapshot: Snapshot{CPULoadPct: ip(50), MemUsedPct: ip(89), DiskUsedPct: ip(89)}}
	if f := Findings(ok); len(f) != 0 {
		t.Fatalf("below every threshold: %+v", f)
	}
	bad := Entry{User: "alice", Device: "d1", Snapshot: Snapshot{CPULoadPct: ip(150), MemUsedPct: ip(90), DiskUsedPct: ip(90)}}
	f := Findings(bad)
	if len(f) != 3 || !strings.Contains(f[0].Message, "alice's disk is 90% full") || f[0].Fix == "" {
		t.Fatalf("%+v", f)
	}
	if f := Findings(Entry{User: "a", Device: "d"}); len(f) != 0 {
		t.Fatal("unknown values must produce no finding, not a false alarm")
	}
}

func TestListScopedByTenantAndStale(t *testing.T) {
	s := New()
	now := time.Now()
	s.Put(Entry{Tenant: "a", User: "alice", Device: "d2", At: now, Snapshot: Snapshot{DiskUsedPct: ip(95)}})
	s.Put(Entry{Tenant: "a", User: "bob", Device: "d1", At: now.Add(-time.Hour)})
	s.Put(Entry{Tenant: "b", User: "eve", Device: "d9", At: now})
	got := s.List("a", now)
	if len(got) != 2 || got[0].Device != "d1" || !got[0].Stale || got[1].Stale || len(got[1].Findings) != 1 {
		t.Fatalf("%+v", got)
	}
	for _, d := range got {
		if d.User == "eve" {
			t.Fatal("another tenant's device")
		}
	}
	s.Put(Entry{Tenant: "a", User: "alice", Device: "d2", At: now, Snapshot: Snapshot{DiskUsedPct: ip(10)}}) // newer report replaces
	if g := s.List("a", now); len(g[1].Findings) != 0 {
		t.Fatal("the latest report must replace the older one")
	}
}

func TestExperienceScoreAndCause(t *testing.T) { // DEX-001, DEX-002 (cause split only)
	ms := func(n int) *int { return &n }
	healthy := Entry{User: "alice", Snapshot: Snapshot{CPULoadPct: ms(20), MemUsedPct: ms(40), ENConnectMs: ms(30), AppOpenMs: map[string]int{"erp": 120}}}
	if x := Score(healthy); x.Score != 100 || x.Cause != "none" || !x.Known {
		t.Fatalf("%+v", x)
	}
	slowNet := healthy
	slowNet.ENConnectMs = ms(400)
	if x := Score(slowNet); x.Cause != "network" || x.Score != 60 || !strings.Contains(x.Explain, "400 ms") {
		t.Fatalf("%+v", x)
	}
	slowApp := healthy
	slowApp.AppOpenMs = map[string]int{"erp": 3000, "wiki": 100}
	if x := Score(slowApp); x.Cause != "app" || !strings.Contains(x.Explain, "erp") || !strings.Contains(x.Explain, "3000") {
		t.Fatalf("a slow app with a healthy device and connection is the app's problem: %+v", x)
	}
	slowDev := healthy
	slowDev.CPULoadPct, slowDev.MemUsedPct = ms(200), ms(95)
	if x := Score(slowDev); x.Cause != "device" || x.Score != 50 {
		t.Fatalf("%+v", x)
	}
	// device trouble outranks an equal-sized network penalty only when it is larger; a slow
	// network with an idle device must not be blamed on the device
	if x := Score(Entry{User: "a", Snapshot: Snapshot{CPULoadPct: ms(10), ENConnectMs: ms(500)}}); x.Cause != "network" {
		t.Fatalf("%+v", x)
	}
}

func TestExperienceNeverInventsBadNews(t *testing.T) {
	x := Score(Entry{User: "alice"})
	if x.Known || x.Score != 100 || x.Cause != "none" || !strings.Contains(x.Explain, "No measurements") {
		t.Fatalf("no data must not look like a problem or like a clean bill of health: %+v", x)
	}
	// only some measurements present: judged on those
	ms := 500
	if x := Score(Entry{User: "a", Snapshot: Snapshot{ENConnectMs: &ms}}); !x.Known || x.Cause != "network" {
		t.Fatalf("%+v", x)
	}
	// scores stay within bounds however bad things get
	bad, one := 999, 5000
	worst := Score(Entry{User: "a", Snapshot: Snapshot{CPULoadPct: &bad, MemUsedPct: &bad, DiskUsedPct: &bad, ENConnectMs: &one, AppOpenMs: map[string]int{"x": one}}})
	if worst.Score < 0 || worst.Score > 100 {
		t.Fatalf("%+v", worst)
	}
}

func TestListCarriesTheExperience(t *testing.T) {
	s := New()
	ms := 400
	s.Put(Entry{Tenant: "a", User: "alice", Device: "d1", At: time.Now(), Snapshot: Snapshot{ENConnectMs: &ms}})
	got := s.List("a", time.Now())
	if len(got) != 1 || got[0].Experience.Cause != "network" {
		t.Fatalf("%+v", got)
	}
}

func TestPathStagesNameTheSlowHop(t *testing.T) { // AGT-018 (DEX-002)
	ip := func(n int) *int { return &n }
	slow := func(mod func(*Entry)) Experience {
		e := Entry{User: "alice", Snapshot: Snapshot{ENConnectMs: ip(400)}}
		mod(&e)
		return Score(e)
	}
	cases := []struct {
		name  string
		mod   func(*Entry)
		cause string
	}{
		{"no stage data", func(e *Entry) {}, "network"},
		{"weak wifi", func(e *Entry) { e.WifiSignalPct = ip(20) }, "wifi"},
		{"slow router", func(e *Entry) { e.GatewayMs = ip(250) }, "local-network"},
		{"slow dns", func(e *Entry) { e.DNSMs = ip(900) }, "dns"},
		{"anchor slow too: the provider", func(e *Entry) { e.AnchorMs = ip(300) }, "isp"},
		{"anchor fast: the node side", func(e *Entry) { e.AnchorMs = ip(20) }, "cloud"},
		{"wifi first when several are bad", func(e *Entry) { e.WifiSignalPct = ip(10); e.GatewayMs = ip(300); e.AnchorMs = ip(300) }, "wifi"},
		{"good wifi and router do not hide the provider", func(e *Entry) { e.WifiSignalPct = ip(90); e.GatewayMs = ip(5); e.AnchorMs = ip(300) }, "isp"},
	}
	for _, c := range cases {
		x := slow(c.mod)
		if x.Cause != c.cause || x.Explain == "" || x.Score >= 100 {
			t.Errorf("%s: got %q (%s), want %q", c.name, x.Cause, x.Explain, c.cause)
		}
	}
	// stage data never makes a fast connection look slow
	if x := Score(Entry{User: "a", Snapshot: Snapshot{ENConnectMs: ip(20), Result: pathprobe.Result{WifiSignalPct: ip(10), GatewayMs: ip(300)}}}); x.Cause != "none" {
		t.Fatalf("%+v", x)
	}
}

func TestAWrongDeviceClockIsAFindingInPlainWords(t *testing.T) { // AGT-045 (GAP-REQ-06)
	n := func(v int) *int { return &v }
	ahead := Entry{Tenant: "t", User: "alice", Device: "d1", Snapshot: Snapshot{ClockSkewSec: n(7 * 60)}}
	f := Findings(ahead)
	if len(f) != 1 || !strings.Contains(f[0].Message, "alice's device clock is about 7 minutes ahead of the real time") || !strings.Contains(f[0].Fix, "automatic date and time") {
		t.Fatalf("%+v", f)
	}
	behind := Entry{User: "bob", Snapshot: Snapshot{ClockSkewSec: n(-3 * 3600)}}
	if f := Findings(behind); len(f) != 1 || !strings.Contains(f[0].Message, "3 hours behind") {
		t.Errorf("%+v", f)
	}
	// a clock that is close, or unknown, is not a finding and is not guessed at
	for _, e := range []Entry{{Snapshot: Snapshot{ClockSkewSec: n(30)}}, {Snapshot: Snapshot{ClockSkewSec: n(-119)}}, {}} {
		if f := Findings(e); len(f) != 0 {
			t.Errorf("%+v gave %+v", e.Snapshot.ClockSkewSec, f)
		}
	}
}
