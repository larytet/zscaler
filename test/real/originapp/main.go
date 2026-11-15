// originapp is the web site the real-environment tests put in the cluster: an HTTPS server that
// answers every request by describing it, and keeps a log a test can read from /__seen.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

func main() {
	addr := flag.String("listen", ":8443", "listen address")
	cert := flag.String("cert", "/tls/tls.crt", "certificate file")
	key := flag.String("key", "/tls/tls.key", "key file")
	flag.Parse()
	var mu sync.Mutex
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/__seen", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprint(w, strings.Join(seen, "\n"))
	})
	// downloads of different kinds, for the file-type tests
	pe := append([]byte("MZ\x90\x00\x03"), make([]byte, 200)...)
	mux.HandleFunc("/dl/setup.exe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(pe)
	})
	mux.HandleFunc("/dl/holiday.jpg", func(w http.ResponseWriter, r *http.Request) { // a program under a picture's name and type
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(pe)
	})
	mux.HandleFunc("/dl/report.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Write([]byte("%PDF-1.7 a clean document"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s %s auth=%q body=%q", r.Method, r.URL.Path, auth, string(b)))
		mu.Unlock()
		// the answer repeats the credential it received, so a test can check it is not handed back
		fmt.Fprintf(w, "origin: %s %s auth=%s body=%d", r.Method, r.URL.Path, auth, len(b))
	})
	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("originapp listening on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
