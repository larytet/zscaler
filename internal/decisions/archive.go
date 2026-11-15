package decisions

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

// Archive keeps a tenant's decision records on disk for a retention period (ADM-006, FW-010, ADM-007):
// one append-only JSON-lines file per tenant and UTC day. The records hold who, what, which rule and
// why, never content, so keeping them is not keeping customer payloads. Captured exchanges and device
// health reports are not archived.
type Archive struct {
	Dir       string
	Retention time.Duration
	Now       func() time.Time

	mu    sync.Mutex
	files map[string]*os.File // tenant dir name + day
}

// DefaultRetention is six months.
const DefaultRetention = 183 * 24 * time.Hour

// OpenArchive prepares the directory. Retention below one day is refused.
func OpenArchive(dir string, retention time.Duration) (*Archive, error) {
	if retention < 24*time.Hour {
		return nil, errors.New("decisions: retention must be at least one day")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Archive{Dir: dir, Retention: retention, files: map[string]*os.File{}}, nil
}

func (a *Archive) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// tenantDir hashes the tenant id: ids are free text and must never reach the file system as they are.
func tenantDir(tenant string) string {
	h := sha256.Sum256([]byte(tenant))
	return hex.EncodeToString(h[:16])
}

func (a *Archive) dayFile(tenant string, day time.Time) string {
	return filepath.Join(a.Dir, tenantDir(tenant), day.UTC().Format("2006-01-02")+".jsonl")
}

// Archived says whether a record kind is kept.
func Archived(kind string) bool { return kind != "capture" && kind != "health" }

// Append writes one record to its tenant's file for the day of the record.
func (a *Archive) Append(r broker.Record) error {
	if !Archived(r.Kind) || r.Tenant == "" {
		return nil
	}
	ts := r.TS
	if ts.IsZero() {
		ts = a.now()
		r.TS = ts
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	path := a.dayFile(r.Tenant, ts)
	f := a.files[path]
	if f == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		a.files[path] = f
		a.closeOld(path)
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

// closeOld keeps the open files to a handful: only today's and yesterday's are written to.
func (a *Archive) closeOld(keep string) {
	if len(a.files) <= 64 {
		return
	}
	for p, f := range a.files {
		if p != keep {
			f.Close()
			delete(a.files, p)
		}
	}
}

// Close closes the open files.
func (a *Archive) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for p, f := range a.files {
		f.Close()
		delete(a.files, p)
	}
}

// Purge deletes day files older than the retention period and reports how many.
func (a *Archive) Purge() int {
	cutoff := a.now().UTC().Add(-a.Retention).Truncate(24 * time.Hour)
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := 0
	dirs, _ := os.ReadDir(a.Dir)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(a.Dir, d.Name()))
		left := 0
		for _, f := range files {
			day, ok := dayOf(f.Name())
			if !ok {
				left++
				continue
			}
			if day.Before(cutoff) {
				p := filepath.Join(a.Dir, d.Name(), f.Name())
				if of := a.files[p]; of != nil {
					of.Close()
					delete(a.files, p)
				}
				if os.Remove(p) == nil {
					removed++
					continue
				}
			}
			left++
		}
		if left == 0 {
			os.Remove(filepath.Join(a.Dir, d.Name()))
		}
	}
	return removed
}

func dayOf(name string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", strings.TrimSuffix(name, ".jsonl"))
	return t, err == nil && strings.HasSuffix(name, ".jsonl")
}

// Query selects records of one tenant. From and To are inclusive; a zero To means now.
type Query struct {
	From, To                time.Time
	User, App, Action, Kind string
	Limit                   int    // default 100, at most 1000
	Cursor                  string // from a previous result
}

// Result is a page of records, oldest first.
type Result struct {
	Records []broker.Record `json:"records"`
	Next    string          `json:"next_cursor,omitempty"` // empty when there is no more
	Oldest  time.Time       `json:"oldest,omitempty"`      // the oldest day that is kept for the tenant
	// Partial is set when the search stopped because it had read its share of data: continue with Next.
	Partial bool `json:"partial,omitempty"`
}

// MaxScan bounds how much one query reads.
const MaxScan = 256 << 20

var ErrBadCursor = errors.New("decisions: bad cursor")

func (a *Archive) days(tenant string) []string {
	files, _ := os.ReadDir(filepath.Join(a.Dir, tenantDir(tenant)))
	var out []string
	for _, f := range files {
		if _, ok := dayOf(f.Name()); ok {
			out = append(out, f.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Query reads the tenant's records in time order.
func (a *Archive) Query(tenant string, q Query) (Result, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	to := q.To
	if to.IsZero() {
		to = a.now()
	}
	var res Result
	res.Records = []broker.Record{}
	days := a.days(tenant)
	if len(days) > 0 {
		res.Oldest, _ = dayOf(days[0])
	}
	startFile, startOff := "", int64(0)
	if q.Cursor != "" {
		i := strings.LastIndex(q.Cursor, ":")
		if i < 0 {
			return res, ErrBadCursor
		}
		off, err := strconv.ParseInt(q.Cursor[i+1:], 10, 64)
		if _, ok := dayOf(q.Cursor[:i] + ".jsonl"); !ok || err != nil || off < 0 {
			return res, ErrBadCursor
		}
		startFile, startOff = q.Cursor[:i]+".jsonl", off
	}
	var scanned int64
	for _, name := range days {
		day, _ := dayOf(name)
		if startFile != "" && name < startFile {
			continue
		}
		if !q.From.IsZero() && day.Add(24*time.Hour).Before(q.From) || day.After(to) {
			continue
		}
		f, err := os.Open(filepath.Join(a.Dir, tenantDir(tenant), name))
		if err != nil {
			continue
		}
		off := int64(0)
		if name == startFile {
			off = startOff
			f.Seek(off, io.SeekStart)
		}
		br := bufio.NewReaderSize(f, 1<<16)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 && line[len(line)-1] == '\n' {
				off += int64(len(line))
				scanned += int64(len(line))
				var r broker.Record
				if json.Unmarshal(line, &r) == nil && r.Tenant == tenant &&
					(q.From.IsZero() || !r.TS.Before(q.From)) && !r.TS.After(to) &&
					(q.User == "" || r.User == q.User) && (q.App == "" || r.App == q.App) &&
					(q.Action == "" || r.Action == q.Action) && (q.Kind == "" || r.Kind == q.Kind) {
					res.Records = append(res.Records, r)
					if len(res.Records) == q.Limit {
						f.Close()
						res.Next = strings.TrimSuffix(name, ".jsonl") + ":" + strconv.FormatInt(off, 10)
						return res, nil
					}
				}
				if scanned > MaxScan {
					f.Close()
					res.Next, res.Partial = strings.TrimSuffix(name, ".jsonl")+":"+strconv.FormatInt(off, 10), true
					return res, nil
				}
			}
			if err != nil {
				break // end of file, or a last line that is not complete yet
			}
		}
		f.Close()
	}
	return res, nil
}

// Restore returns the most recent records of every tenant, oldest first within a tenant, at most max
// per tenant, to refill the in-memory view after a restart.
func (a *Archive) Restore(max int) []broker.Record {
	var out []broker.Record
	dirs, _ := os.ReadDir(a.Dir)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(a.Dir, d.Name()))
		var names []string
		for _, f := range files {
			if _, ok := dayOf(f.Name()); ok {
				names = append(names, f.Name())
			}
		}
		sort.Strings(names)
		var chunks [][]broker.Record
		n := 0
		for i := len(names) - 1; i >= 0 && n < max; i-- {
			b, err := os.ReadFile(filepath.Join(a.Dir, d.Name(), names[i]))
			if err != nil {
				continue
			}
			var recs []broker.Record
			for _, l := range strings.Split(string(b), "\n") {
				var r broker.Record
				if l != "" && json.Unmarshal([]byte(l), &r) == nil {
					recs = append(recs, r)
				}
			}
			chunks = append(chunks, recs)
			n += len(recs)
		}
		var all []broker.Record
		for i := len(chunks) - 1; i >= 0; i-- {
			all = append(all, chunks[i]...)
		}
		if len(all) > max {
			all = all[len(all)-max:]
		}
		out = append(out, all...)
	}
	return out
}

// Describe is a one-line summary for logs.
func (a *Archive) Describe() string {
	return fmt.Sprintf("decision archive in %s, kept %d days", a.Dir, int(a.Retention/(24*time.Hour)))
}
