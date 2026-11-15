// stubbrowser stands in for Chromium in tests of the workspace launcher. It records how it was
// started, then behaves like a page that wants a private app through the proxy it was given.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func main() {
	profile, pac := "", ""
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "--user-data-dir="); ok {
			profile = v
		}
		if v, ok := strings.CutPrefix(a, "--proxy-pac-url="); ok {
			pac = v
		}
	}
	if profile == "" {
		fmt.Fprintln(os.Stderr, "no --user-data-dir")
		os.Exit(2)
	}
	os.WriteFile(filepath.Join(profile, "stub-args.txt"), []byte(strings.Join(os.Args[1:], "\n")), 0o600)
	os.WriteFile(filepath.Join(profile, "personal-data.txt"), []byte("cookies and history of this workspace"), 0o600)

	result := "no-pac"
	if pac != "" {
		result = try(pac, os.Getenv("STUB_APP"), os.Getenv("STUB_PORT"))
	}
	os.WriteFile(filepath.Join(profile, "stub-result.txt"), []byte(result), 0o600)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-ch:
	case <-time.After(10 * time.Minute):
	}
}

// try fetches the proxy auto-config the way a browser would, finds the SOCKS server it names
// for ".ztx" hosts, and asks it for app:port. It returns "ok" when an echo comes back.
func try(pacURL, app, port string) string {
	resp, err := http.Get(pacURL)
	if err != nil {
		return "pac-error"
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`SOCKS5 ([0-9.:]+)`).FindStringSubmatch(string(b))
	if m == nil {
		return "pac-has-no-socks"
	}
	c, err := net.DialTimeout("tcp", m[1], 3*time.Second)
	if err != nil {
		return "socks-unreachable"
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	var r [2]byte
	io.ReadFull(c, r[:])
	var p int
	fmt.Sscan(port, &p)
	req := append([]byte{5, 1, 0, 3, byte(len(app))}, app...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(p))
	c.Write(append(req, pb[:]...))
	var resp2 [10]byte
	if _, err := io.ReadFull(c, resp2[:]); err != nil {
		return "socks-error"
	}
	if resp2[1] != 0 {
		return fmt.Sprintf("refused-%d", resp2[1])
	}
	c.Write([]byte("p"))
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		return "no-echo"
	}
	return "ok"
}
