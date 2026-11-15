// Package audit is an append-only, hash-chained admin audit log
// (DESIGN.md D5.5). Altering or deleting a record breaks the chain.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Event struct {
	Seq    int             `json:"seq"`
	TS     time.Time       `json:"ts"`
	Tenant string          `json:"tenant"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Object string          `json:"object"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
	Prev   string          `json:"prev"`
	Hash   string          `json:"hash"`
}

func (e Event) compute() string {
	c := e
	c.Hash = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Log writes JSON lines to a file. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  int
	prev string
	now  func() time.Time
}

// Open resumes an existing log, verifying it first.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	l := &Log{now: now}
	if f, err := os.Open(path); err == nil {
		last, n, verr := verify(f)
		f.Close()
		if verr != nil {
			return nil, fmt.Errorf("audit log %s is corrupt: %w", path, verr)
		}
		l.prev, l.seq = last, n
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Close() error { return l.f.Close() }

func (l *Log) Append(tenant, actor, action, object string, before, after any) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{Seq: l.seq + 1, TS: l.now().UTC(), Tenant: tenant, Actor: actor, Action: action, Object: object, Prev: l.prev}
	var err error
	if before != nil {
		if e.Before, err = json.Marshal(before); err != nil {
			return e, err
		}
	}
	if after != nil {
		if e.After, err = json.Marshal(after); err != nil {
			return e, err
		}
	}
	e.Hash = e.compute()
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return e, err
	}
	if err := l.f.Sync(); err != nil {
		return e, err
	}
	l.seq, l.prev = e.Seq, e.Hash
	return e, nil
}

// Verify checks the whole chain. It returns the number of records.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	_, n, err := verify(f)
	return n, err
}

func verify(r io.Reader) (last string, n int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return "", n, fmt.Errorf("record %d: %w", n+1, err)
		}
		if e.Seq != n+1 {
			return "", n, fmt.Errorf("record %d: sequence gap (found %d)", n+1, e.Seq)
		}
		if e.Prev != last {
			return "", n, fmt.Errorf("record %d: chain broken", e.Seq)
		}
		if e.Hash != e.compute() {
			return "", n, fmt.Errorf("record %d: content altered", e.Seq)
		}
		last, n = e.Hash, n+1
	}
	if err := sc.Err(); err != nil {
		return "", n, err
	}
	return last, n, nil
}

var ErrCorrupt = errors.New("audit: corrupt")

// ReadAll returns every record for a tenant in order ("" for all tenants).
func ReadAll(path, tenant string) ([]Event, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && (tenant == "" || e.Tenant == tenant) {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}
