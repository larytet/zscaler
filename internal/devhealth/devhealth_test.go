package devhealth

import (
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
