//go:build perf

package en

import (
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/larytet/zscaler/internal/audit"
	"github.com/larytet/zscaler/internal/cp"
	"github.com/larytet/zscaler/internal/pki"
	"github.com/larytet/zscaler/internal/policy"
)

// PERF-006: a policy change reaches 20 ENs within 5 s at the default poll interval.
func TestPerf006PolicyPropagation(t *testing.T) {
	st := seed(t)
	al, _ := audit.Open(filepath.Join(t.TempDir(), "a"), nil)
	defer al.Close()
	api := &cp.API{Store: st, Audit: al, Tokens: pki.NewTokens(nil, time.Hour)}
	ca, _ := pki.NewCA("ca", nil)
	signer, _ := pki.LoadOrCreateSigner(t.TempDir())
	srv := httptest.NewUnstartedServer((&cp.Enrol{API: api, CA: ca, Rev: pki.NewRevocations(nil), PolicyKey: signer}).Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}
	srv.StartTLS()
	defer srv.Close()
	k, _ := enKey(t)
	der, _ := ca.Sign(&k.PublicKey, pki.Identity{Tenant: "platform", Subject: "en", Device: "en", Role: pki.RoleEN}, time.Hour, "localhost")
	cfg := &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}

	const n = 20
	every := DefaultSyncEvery
	states := make([]*SyncState, n)
	stop := make(chan struct{})
	defer close(stop)
	for i := range states {
		states[i] = NewSyncState()
		p := &Poller{URL: srv.URL, TLS: cfg, State: states[i], PolicyPub: &signer.PublicKey}
		go func(i int) { // spread the starts across one interval, as real nodes would be
			time.Sleep(time.Duration(i) * every / n)
			p.Run(every, stop, nil)
		}(i)
	}
	time.Sleep(every + 500*time.Millisecond) // everyone has synced once

	start := time.Now()
	st.SetUserDisabled("t1", "alice", true) // a change that must reach every node
	var wg sync.WaitGroup
	took := make([]time.Duration, n)
	for i := range states {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for time.Since(start) < 3*every {
				if u, _ := states[i].User("t1", "alice"); u.Disabled {
					took[i] = time.Since(start)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	var worst time.Duration
	for _, d := range took {
		if d == 0 {
			t.Fatal("a node never saw the change")
		}
		if d > worst {
			worst = d
		}
	}
	t.Logf("PERF-006 change reached %d nodes in at most %v with a %v poll interval (target <= 5s)", n, worst.Round(time.Millisecond), every)
	if worst > 5*time.Second {
		t.Errorf("PERF-006 missed: %v", worst)
	}
	_ = policy.Private
}
