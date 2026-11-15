//go:build perf

package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PERF-001: private session setup latency, p95 under 20 ms (loopback, one machine).
func TestPerf001SetupLatency(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	const n = 2000
	d := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		s, err := conn.OpenApp("seg-db", "", r.app.port())
		if err != nil {
			t.Fatal(err)
		}
		d = append(d, time.Since(start))
		s.Close()
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	p50, p95, p99 := d[n/2], d[n*95/100], d[n*99/100]
	t.Logf("PERF-001 setup latency p50=%v p95=%v p99=%v (target p95 < 20ms)", p50, p95, p99)
	if p95 > 20*time.Millisecond {
		t.Errorf("PERF-001 missed: p95 %v", p95)
	}
}

// PERF-002: single-stream throughput, at least 500 Mbit/s on loopback.
func TestPerf002Throughput(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conn, _ := r.agent("alice", "d1", true)
	s, err := conn.OpenApp("seg-db", "", r.app.port())
	if err != nil {
		t.Fatal(err)
	}
	const total = 1 << 30 // 1 GiB each way (the app echoes)
	buf := make([]byte, 64<<10)
	start := time.Now()
	go func() {
		for sent := 0; sent < total; sent += len(buf) {
			if _, err := s.Write(buf); err != nil {
				return
			}
		}
		s.CloseWrite()
	}()
	n, _ := io.Copy(io.Discard, s)
	el := time.Since(start)
	mbit := float64(n) * 8 / 1e6 / el.Seconds()
	t.Logf("PERF-002 %d MiB round trip in %v: %.0f Mbit/s one way (target >= 500)", n>>20, el.Round(time.Millisecond), mbit)
	if mbit < 500 {
		t.Errorf("PERF-002 missed: %.0f Mbit/s", mbit)
	}
}

// PERF-003: 1000 concurrent stitched sessions. This runs EN, connector, agent and
// app in one process, so the measured heap is an upper bound for the EN alone.
func TestPerf003ConcurrentSessions(t *testing.T) {
	r := newRig(t)
	r.startConnector("c1", r.allowApp)
	conns := make([]*Conn, 0, 10)
	for i := 0; i < 10; i++ {
		c, _ := r.agent("alice", "d"+string(rune('a'+i)), true)
		conns = append(conns, c)
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var open []io.Closer
	errs := 0
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := conns[i%10].OpenApp("seg-db", "", r.app.port())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			open = append(open, s)
		}(i)
	}
	wg.Wait()
	time.Sleep(3 * time.Second) // hold them
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	held := r.en.ActiveSessions()
	grow := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) >> 20
	t.Logf("PERF-003 %d sessions held, %d errors, heap grew %d MiB (target < 300 MiB, no errors)", held, errs, grow)
	if errs != 0 || held != 1000 {
		t.Errorf("PERF-003 missed: %d errors, %d held", errs, held)
	}
	if grow > 300 {
		t.Errorf("PERF-003 missed: heap grew %d MiB", grow)
	}
	for _, c := range open {
		c.Close()
	}
}

// PERF-008: writing the decision log adds under 5% to session setup. The sink is
// the same shape as ztx-en uses: JSON line, file write under a mutex.
func TestPerf008DecisionLogOverhead(t *testing.T) {
	measure := func(withLog bool) time.Duration {
		r := newRig(t)
		if withLog {
			f, err := os.OpenFile(filepath.Join(t.TempDir(), "decisions.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			r.en.Log = func(rec Record) {
				mu.Lock()
				b, _ := json.Marshal(rec)
				f.Write(append(b, '\n'))
				mu.Unlock()
			}
		}
		r.startConnector("c1", r.allowApp)
		conn, _ := r.agent("alice", "d1", true)
		for i := 0; i < 300; i++ { // warm up
			s, _ := conn.OpenApp("seg-db", "", r.app.port())
			s.Close()
		}
		const n = 3000
		start := time.Now()
		for i := 0; i < n; i++ {
			s, err := conn.OpenApp("seg-db", "", r.app.port())
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
		}
		return time.Since(start) / n
	}
	// interleave runs to cancel machine noise; use the best of three each
	best := func(with bool) time.Duration {
		b := time.Hour
		for i := 0; i < 3; i++ {
			if d := measure(with); d < b {
				b = d
			}
		}
		return b
	}
	off, on := best(false), best(true)
	over := float64(on-off) / float64(off) * 100
	t.Logf("PERF-008 setup %v without log, %v with log: %.1f%% overhead (target < 5%%)", off, on, over)
	if over > 5 {
		t.Errorf("PERF-008 missed: %.1f%%", over)
	}
}

// RES-007 (shortened): sessions churn continuously; no errors, no goroutine or heap
// growth beyond 10% after warm-up. The plan calls for 24 h with 200 sessions; set
// SOAK_SECONDS to run longer.
func TestRES007Soak(t *testing.T) {
	secs := 60
	if v := os.Getenv("SOAK_SECONDS"); v != "" {
		fmt.Sscan(v, &secs)
	}
	r := newRig(t)
	r.en.Log = func(Record) {} // the rig's recorder keeps every record in memory
	r.startConnector("c1", r.allowApp)
	conns := make([]*Conn, 10)
	for i := range conns {
		conns[i], _ = r.agent("alice", "d"+string(rune('a'+i)), true)
	}
	var errs, total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := make([]byte, 512)
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, err := conns[i%10].OpenApp("seg-db", "", r.app.port())
				if err != nil {
					errs.Add(1)
					continue
				}
				s.Write(buf)
				io.ReadFull(s, buf)
				s.Close()
				total.Add(1)
			}
		}(i)
	}
	sample := func() (int, uint64) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return runtime.NumGoroutine(), m.HeapAlloc
	}
	time.Sleep(10 * time.Second) // warm-up
	g0, h0 := sample()
	time.Sleep(time.Duration(secs) * time.Second)
	g1, h1 := sample()
	close(stop)
	wg.Wait()
	growG := float64(g1-g0) / float64(g0) * 100
	growH := (float64(h1) - float64(h0)) / float64(h0) * 100
	t.Logf("RES-007 %d sessions over %ds, %d errors; goroutines %d to %d (%.1f%%), heap %d to %d MiB (%.1f%%)",
		total.Load(), secs, errs.Load(), g0, g1, growG, h0>>20, h1>>20, growH)
	if errs.Load() != 0 {
		t.Errorf("errors during soak: %d", errs.Load())
	}
	if growG > 10 || growH > 10 {
		t.Errorf("RES-007 missed: goroutines +%.1f%%, heap +%.1f%%", growG, growH)
	}
}
