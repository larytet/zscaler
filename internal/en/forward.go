package en

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

// Forwarder batches records and ships them to the control plane. The buffer
// is bounded: when the control plane is unreachable the oldest records are
// dropped (local decision logs on disk are the durable copy).
type Forwarder struct {
	URL  string
	TLS  *tls.Config
	Max  int // default 10000
	HTTP *http.Client

	mu      sync.Mutex
	buf     []broker.Record
	Dropped int
}

func (f *Forwarder) Add(r broker.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Max == 0 {
		f.Max = 10000
	}
	if len(f.buf) >= f.Max {
		f.buf = f.buf[1:]
		f.Dropped++
	}
	f.buf = append(f.buf, r)
}

func (f *Forwarder) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: f.TLS}}
}

// Flush sends up to 1000 records. On failure they stay queued.
func (f *Forwarder) Flush() error {
	f.mu.Lock()
	n := len(f.buf)
	if n > 1000 {
		n = 1000
	}
	batch := append([]broker.Record(nil), f.buf[:n]...)
	f.mu.Unlock()
	if n == 0 {
		return nil
	}
	b, _ := json.Marshal(batch)
	resp, err := f.client().Post(f.URL+"/ingest/records", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ingest: control plane returned %d", resp.StatusCode)
	}
	f.mu.Lock()
	if len(f.buf) >= n {
		f.buf = f.buf[n:]
	}
	f.mu.Unlock()
	return nil
}

func (f *Forwarder) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.buf)
}

func (f *Forwarder) Run(every time.Duration, stop <-chan struct{}, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := f.Flush(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
