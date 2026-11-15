package pathprobe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

const route = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0102A8C0	0003	0	0	600	00000000	0	0	0
wlan0	0002A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
`

const wireless = `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlan0: 0000   35.  -75.  -256        0      0      0      0      0        0
`

func TestParsers(t *testing.T) {
	if g := ParseGateway(route); g != "192.168.2.1" {
		t.Fatalf("gateway %q", g)
	}
	if g := ParseGateway("Iface\tDestination\tGateway\tFlags\nlo\t0000007F\t00000000\t0001\n"); g != "" {
		t.Fatalf("no default route: %q", g)
	}
	if p := ParseWireless(wireless); p == nil || *p != 50 {
		t.Fatalf("wifi %v", p)
	}
	if ParseWireless("Inter-| sta-|\n face | tus |\n") != nil {
		t.Fatal("no interfaces must give unknown")
	}
	if ParseWireless("garbage") != nil || ParseGateway("garbage") != "" {
		t.Fatal("garbage must give unknown")
	}
}

func TestRunMeasuresEachStage(t *testing.T) { // AGT-018 (DEX-002)
	var dialed []string
	o := Options{
		ResolveName: "en.example.com", Anchor: "anchor.example:443", Timeout: time.Second,
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/proc/net/route":
				return []byte(route), nil
			case "/proc/net/wireless":
				return []byte(wireless), nil
			}
			return nil, errors.New("no")
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			if addr == "192.168.2.1:53" {
				return nil, errors.New("connection refused") // the router answers, so it counts
			}
			return nil, errors.New("i/o timeout")
		},
		Lookup: func(ctx context.Context, h string) ([]string, error) { return []string{"203.0.113.9"}, nil },
	}
	r := Run(context.Background(), o)
	if r.WifiSignalPct == nil || *r.WifiSignalPct != 50 || r.GatewayMs == nil || r.DNSMs == nil {
		t.Fatalf("%+v", r)
	}
	if r.AnchorMs != nil {
		t.Fatal("an anchor that times out must be unknown, not zero")
	}
	for _, d := range dialed {
		if d == "203.0.113.9:443" {
			t.Fatal("only the stages asked for are contacted")
		}
	}
}

func TestNothingContactedWithoutAnAnchorOrResolvableName(t *testing.T) {
	contacted := false
	r := Run(context.Background(), Options{ResolveName: "127.0.0.1",
		ReadFile: func(string) ([]byte, error) { return nil, errors.New("no") },
		Dial:     func(context.Context, string, string) (net.Conn, error) { contacted = true; return nil, errors.New("x") },
		Lookup:   func(context.Context, string) ([]string, error) { contacted = true; return nil, errors.New("x") }})
	if contacted || r.AnchorMs != nil || r.DNSMs != nil || r.GatewayMs != nil || r.WifiSignalPct != nil {
		t.Fatalf("%+v contacted=%v", r, contacted)
	}
}
