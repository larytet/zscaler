package en

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/larytet/zscaler/internal/broker"
)

func TestForwarderRetriesAndKeepsOrder(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var got []broker.Record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var b []broker.Record
		json.NewDecoder(r.Body).Decode(&b)
		got = append(got, b...)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	f := &Forwarder{URL: srv.URL}
	for i := 0; i < 3; i++ {
		f.Add(broker.Record{Tenant: "t", User: string(rune('a' + i))})
	}
	if err := f.Flush(); err == nil {
		t.Fatal("flush should fail while the control plane is down")
	}
	if f.Pending() != 3 {
		t.Fatalf("records lost on failure: %d pending", f.Pending())
	}
	fail.Store(false)
	if err := f.Flush(); err != nil || f.Pending() != 0 {
		t.Fatalf("%v pending %d", err, f.Pending())
	}
	if len(got) != 3 || got[0].User != "a" || got[2].User != "c" {
		t.Fatalf("order or content wrong: %+v", got)
	}
}

func TestForwarderBoundedBuffer(t *testing.T) {
	f := &Forwarder{Max: 5}
	for i := 0; i < 8; i++ {
		f.Add(broker.Record{User: string(rune('a' + i))})
	}
	if f.Pending() != 5 || f.Dropped != 3 {
		t.Fatalf("pending %d dropped %d", f.Pending(), f.Dropped)
	}
	if f.buf[0].User != "d" {
		t.Fatalf("oldest records should be dropped first, head is %q", f.buf[0].User)
	}
}
