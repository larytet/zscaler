// Package pathprobe measures the stages between a device and the internet (DEX-002, basic):
// Wi-Fi signal, the local router, name resolution, and optionally a neutral anchor on the
// internet. Together with the existing time to reach the enforcement node and to open apps,
// they let the platform say which stage is slow. Probes are small and run with the posture
// report (every five minutes by default); an anchor is contacted only if the admin names one.
package pathprobe

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Result holds what was measured. Nil means not measured or not available.
type Result struct {
	WifiSignalPct *int `json:"wifi_signal_pct,omitempty"` // link quality of the Wi-Fi interface, 0 to 100
	GatewayMs     *int `json:"gateway_ms,omitempty"`      // TCP round trip to the default router
	DNSMs         *int `json:"dns_ms,omitempty"`          // time to resolve the enforcement node's name
	AnchorMs      *int `json:"anchor_ms,omitempty"`       // TCP connect to the anchor the admin chose
}

func ip(n int) *int { return &n }

// Options say what to probe.
type Options struct {
	ResolveName string // host name to resolve (the enforcement node's name); IP literals are skipped
	Anchor      string // host:port reachable from any network, chosen by the admin; empty = none
	Timeout     time.Duration
	// Test hooks; nil uses the real system.
	ReadFile func(string) ([]byte, error)
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Lookup   func(ctx context.Context, host string) ([]string, error)
}

// Run takes the measurements. It never returns an error: a stage that fails is left unknown, and a
// stage that is reachable only slowly is reported as slow.
func Run(ctx context.Context, o Options) Result {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.Dial == nil {
		d := net.Dialer{Timeout: o.Timeout}
		o.Dial = d.DialContext
	}
	if o.Lookup == nil {
		o.Lookup = net.DefaultResolver.LookupHost
	}
	var r Result
	if b, err := o.ReadFile("/proc/net/wireless"); err == nil {
		r.WifiSignalPct = ParseWireless(string(b))
	}
	if b, err := o.ReadFile("/proc/net/route"); err == nil {
		if gw := ParseGateway(string(b)); gw != "" {
			r.GatewayMs = tcpRTT(ctx, o, gw, []string{"53", "80", "443"})
		}
	}
	if h := o.ResolveName; h != "" && net.ParseIP(h) == nil && h != "localhost" {
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		start := time.Now()
		if _, err := o.Lookup(c, h); err == nil {
			r.DNSMs = ip(int(time.Since(start).Milliseconds()))
		}
		cancel()
	}
	if o.Anchor != "" {
		if host, port, err := net.SplitHostPort(o.Anchor); err == nil {
			r.AnchorMs = tcpRTT(ctx, o, host, []string{port})
		}
	}
	return r
}

// tcpRTT times a TCP connect. A refused connection still proves the host answered, so it counts;
// a timeout means the stage is unreachable (nil). The fastest port wins, since a router usually
// answers on only some of them.
func tcpRTT(ctx context.Context, o Options, host string, ports []string) *int {
	best := -1
	for _, p := range ports {
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		start := time.Now()
		conn, err := o.Dial(c, "tcp", net.JoinHostPort(host, p))
		d := int(time.Since(start).Milliseconds())
		cancel()
		if err == nil {
			conn.Close()
		} else if !refused(err) {
			continue
		}
		if best < 0 || d < best {
			best = d
		}
	}
	if best < 0 {
		return nil
	}
	return ip(best)
}

func refused(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

// ParseGateway returns the default router address from /proc/net/route text, or "".
func ParseGateway(text string) string {
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[1] != "00000000" {
			continue
		}
		if flags, err := strconv.ParseUint(f[3], 16, 32); err != nil || flags&2 == 0 { // RTF_GATEWAY
			continue
		}
		g, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || g == 0 {
			continue
		}
		// the address is stored little-endian
		return net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24)).String()
	}
	return ""
}

// ParseWireless returns the best link quality (as a percentage of 70) from /proc/net/wireless.
func ParseWireless(text string) *int {
	best := -1
	for i, line := range strings.Split(text, "\n") {
		if i < 2 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSuffix(f[2], "."), 64)
		if err != nil {
			continue
		}
		p := int(q / 70 * 100)
		if p > 100 {
			p = 100
		}
		if p < 0 {
			p = 0
		}
		if p > best {
			best = p
		}
	}
	if best < 0 {
		return nil
	}
	return ip(best)
}
