//go:build perf

package broker

import (
	"io"
	"runtime"
	"sort"
	"sync"
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
