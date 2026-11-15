//go:build perf

package webproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PERF-007: at least 1000 small requests per second on one core. Client, proxy and
// origin all share that core here, so this is conservative.
func TestPerf007ProxyThroughput(t *testing.T) {
	r := newRig(t)
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	const clients = 16
	var done atomic.Int64
	var errs atomic.Int64
	stop := time.Now().Add(4 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := tls.Dial("tcp", r.addr, r.cli)
			if err != nil {
				errs.Add(1)
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			req := fmt.Sprintf("GET %s/x HTTP/1.1\r\nHost: %s\r\n\r\n", r.origin.URL, hostport(r.origin.URL))
			for time.Now().Before(stop) {
				io.WriteString(c, req)
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					errs.Add(1)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	rps := float64(done.Load()) / 4
	t.Logf("PERF-007 %.0f requests/s on one core, %d errors (target >= 1000)", rps, errs.Load())
	if rps < 1000 || errs.Load() != 0 {
		t.Errorf("PERF-007 missed")
	}
}
