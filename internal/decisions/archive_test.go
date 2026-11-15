package decisions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

func day(d int) time.Time { return time.Date(2026, 6, d, 10, 0, 0, 0, time.UTC) }

func arec(tenant, user, action string, ts time.Time) broker.Record {
	return broker.Record{Tenant: tenant, Kind: "private", User: user, Action: action, App: "erp", Event: "open", TS: ts}
}

func newArchive(t *testing.T, now time.Time) *Archive {
	a, err := OpenArchive(filepath.Join(t.TempDir(), "d"), DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return now }
	t.Cleanup(a.Close)
	return a
}

func TestArchiveKeepsAndSearchesByDate(t *testing.T) { // AGT-026 (ADM-006, FW-010)
	a := newArchive(t, day(20))
	for d := 1; d <= 10; d++ {
		for i := 0; i < 5; i++ {
			user := "alice"
			if i%2 == 1 {
				user = "bob"
			}
			action := "allow"
			if i == 4 {
				action = "deny"
			}
			if err := a.Append(arec("t1", user, action, day(d).Add(time.Duration(i)*time.Minute))); err != nil {
				t.Fatal(err)
			}
		}
	}
	all, err := a.Query("t1", Query{Limit: 1000})
	if err != nil || len(all.Records) != 50 || all.Next != "" {
		t.Fatalf("%d %v %q", len(all.Records), err, all.Next)
	}
	for i := 1; i < len(all.Records); i++ {
		if all.Records[i].TS.Before(all.Records[i-1].TS) {
			t.Fatal("records must come oldest first")
		}
	}
	if !all.Oldest.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("oldest %v", all.Oldest)
	}
	// a date range, a user, an action
	r, _ := a.Query("t1", Query{From: day(3), To: day(5).Add(time.Hour), Limit: 1000})
	if len(r.Records) != 15 {
		t.Fatalf("days 3 to 5: %d", len(r.Records))
	}
	if r, _ = a.Query("t1", Query{User: "bob", Limit: 1000}); len(r.Records) != 20 {
		t.Fatalf("bob: %d", len(r.Records))
	}
	if r, _ = a.Query("t1", Query{Action: "deny", From: day(9), Limit: 1000}); len(r.Records) != 2 {
		t.Fatalf("denials from day 9: %d", len(r.Records))
	}
	// a range inside one day cuts at the minute, not at the day
	if r, _ = a.Query("t1", Query{From: day(4).Add(90 * time.Second), To: day(4).Add(3*time.Minute + time.Second), Limit: 1000}); len(r.Records) != 2 {
		t.Fatalf("minutes: %d", len(r.Records))
	}
	// a page at a time, by cursor, finds every record once
	var got []broker.Record
	cur := ""
	for pages := 0; pages < 100; pages++ {
		p, err := a.Query("t1", Query{Limit: 7, Cursor: cur})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p.Records...)
		if p.Next == "" {
			break
		}
		cur = p.Next
	}
	if len(got) != 50 {
		t.Fatalf("paging returned %d records", len(got))
	}
	seen := map[string]bool{}
	for _, g := range got {
		k := g.TS.String() + g.User
		if seen[k] {
			t.Fatalf("a record came twice: %s", k)
		}
		seen[k] = true
	}
}

func TestRetentionDeletesOldDaysOnly(t *testing.T) { // AGT-026
	a := newArchive(t, day(28))
	a.Retention = 10 * 24 * time.Hour
	for _, d := range []int{1, 10, 17, 18, 19, 25} {
		a.Append(arec("t1", "alice", "allow", day(d)))
	}
	a.Append(arec("t2", "zed", "allow", day(2)))
	removed := a.Purge() // now is the 28th: the 17th and earlier are past ten days
	if removed != 4 {
		t.Fatalf("removed %d day files, expected the 1st, 2nd (other tenant), 10th and 17th", removed)
	}
	r, _ := a.Query("t1", Query{Limit: 100})
	if len(r.Records) != 3 || !r.Oldest.Equal(time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%d records, oldest %v", len(r.Records), r.Oldest)
	}
	// a tenant with nothing left leaves no directory behind
	if _, err := os.Stat(filepath.Join(a.Dir, tenantDir("t2"))); err == nil {
		t.Fatal("an empty tenant directory was left")
	}
	if a.Purge() != 0 {
		t.Fatal("a second purge must find nothing")
	}
	if _, err := OpenArchive(t.TempDir(), time.Hour); err == nil {
		t.Fatal("a retention under a day must be refused")
	}
}

func TestArchiveIsolatesTenantsAndNamesSafely(t *testing.T) { // AGT-026
	a := newArchive(t, day(20))
	hostile := "../../../etc/passwd"
	a.Append(arec("t1", "alice", "allow", day(1)))
	a.Append(arec(hostile, "mallory", "allow", day(1)))
	a.Append(arec("t2", "zed", "deny", day(1)))
	if r, _ := a.Query("t1", Query{Limit: 100}); len(r.Records) != 1 || r.Records[0].User != "alice" {
		t.Fatalf("%+v", r.Records)
	}
	if r, _ := a.Query(hostile, Query{Limit: 100}); len(r.Records) != 1 || r.Records[0].User != "mallory" {
		t.Fatalf("%+v", r.Records)
	}
	// nothing was written outside the archive directory
	filepath.Walk(filepath.Dir(a.Dir), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasPrefix(p, a.Dir) {
			t.Errorf("a file outside the archive: %s", p)
		}
		return nil
	})
	// a record of another tenant planted in this tenant's file is not returned
	f := a.dayFile("t1", day(1))
	os.WriteFile(f, append(mustRead(t, f), []byte(`{"tenant":"t2","kind":"private","user":"planted","action":"allow","ts":"2026-06-01T11:00:00Z"}`+"\n")...), 0o600)
	if r, _ := a.Query("t1", Query{Limit: 100}); len(r.Records) != 1 {
		t.Fatalf("a planted record of another tenant was returned: %+v", r.Records)
	}
	// permissions
	if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(f)); info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", info.Mode().Perm())
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestArchiveKeepsWhatIsAskedAndNotCapturesOrHealth(t *testing.T) { // AGT-026
	a := newArchive(t, day(20))
	for _, k := range []string{"private", "web", "connector", "posture", "capture", "health"} {
		a.Append(broker.Record{Tenant: "t1", Kind: k, User: "u", Action: "info", TS: day(1)})
	}
	r, _ := a.Query("t1", Query{Limit: 100})
	kinds := map[string]bool{}
	for _, x := range r.Records {
		kinds[x.Kind] = true
	}
	if len(r.Records) != 4 || kinds["capture"] || kinds["health"] {
		t.Fatalf("%v", kinds)
	}
	if strings.Contains(string(mustRead(t, a.dayFile("t1", day(1)))), "capture") {
		t.Fatal("captured traffic must never be on disk")
	}
}

func TestArchiveSurvivesARestartAndRefillsMemory(t *testing.T) { // AGT-026
	dir := filepath.Join(t.TempDir(), "d")
	a, _ := OpenArchive(dir, DefaultRetention)
	s := New()
	s.SetArchive(a)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		s.Add(arec("t1", "alice", "allow", now.Add(-time.Duration(30-i)*time.Minute)))
	}
	s.Add(arec("t2", "zed", "deny", now))
	a.Close()

	a2, _ := OpenArchive(dir, DefaultRetention)
	defer a2.Close()
	r, _ := a2.Query("t1", Query{Limit: 100})
	if len(r.Records) != 30 {
		t.Fatalf("after a restart: %d", len(r.Records))
	}
	s2 := New()
	s2.SetArchive(a2)
	if n := s2.Restore(20); n != 21 { // 20 of t1 (the newest), 1 of t2
		t.Fatalf("restored %d", n)
	}
	e, _ := s2.Query("t1", Filter{Limit: 100})
	if len(e) != 20 || !e[len(e)-1].TS.Equal(now.Add(-time.Minute)) {
		t.Fatalf("the newest 20 must be back, oldest first: %d", len(e))
	}
	if e2, _ := s2.Query("t2", Filter{Limit: 100}); len(e2) != 1 || e2[0].User != "zed" {
		t.Fatalf("%+v", e2)
	}
}

func TestArchiveCopesWithDamagedFilesAndBadCursors(t *testing.T) { // AGT-026
	a := newArchive(t, day(20))
	a.Append(arec("t1", "alice", "allow", day(1)))
	f := a.dayFile("t1", day(1))
	os.WriteFile(f, append(mustRead(t, f), []byte("this is not json\n{\"tenant\":\"t1\",\"user\":\"half")...), 0o600) // a damaged line and a last line still being written
	a.Append(arec("t1", "bob", "allow", day(2)))
	r, err := a.Query("t1", Query{Limit: 100})
	if err != nil || len(r.Records) != 2 {
		t.Fatalf("%d %v", len(r.Records), err)
	}
	for _, c := range []string{"x", "2026-13-40:5", "2026-06-01:-3", "../../x:1", "2026-06-01:abc", ":"} {
		if _, err := a.Query("t1", Query{Cursor: c}); err != ErrBadCursor {
			t.Errorf("cursor %q: %v", c, err)
		}
	}
	if r, err := a.Query("nobody", Query{}); err != nil || len(r.Records) != 0 {
		t.Fatalf("an unknown tenant has no records: %v %v", r.Records, err)
	}
}

func TestArchiveConcurrentUse(t *testing.T) { // AGT-026
	a := newArchive(t, day(20))
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				a.Append(arec(fmt.Sprintf("t%d", g%2), "u", "allow", day(1+i%3)))
				if i%50 == 0 {
					a.Query("t0", Query{Limit: 10})
					a.Purge()
				}
			}
		}(g)
	}
	wg.Wait()
	r0, _ := a.Query("t0", Query{Limit: 1000})
	r1, _ := a.Query("t1", Query{Limit: 1000})
	if len(r0.Records)+len(r1.Records) != 800 {
		t.Fatalf("%d + %d records", len(r0.Records), len(r1.Records))
	}
}
