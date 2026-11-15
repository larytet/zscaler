// Package devhealth holds the latest device health numbers (DEX-003, basic) and turns
// them into plain-language findings. The agent measures CPU load, memory and disk on
// Linux; on other systems the fields stay unknown (nil) and nothing is claimed.
package devhealth

import (
	"fmt"
	"github.com/larytet/zscaler/internal/clockhint"
	"github.com/larytet/zscaler/internal/pathprobe"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is what the agent reports. Percentages are 0 to 100; nil means unknown.
type Snapshot struct {
	CPULoadPct  *int `json:"cpu_load_pct,omitempty"`  // 1-minute load average as a percentage of core count
	MemUsedPct  *int `json:"mem_used_pct,omitempty"`  // memory in use, not counting reclaimable cache
	DiskUsedPct *int `json:"disk_used_pct,omitempty"` // the volume holding the home directory
	// Measured by the agent from its own traffic (DEX-001), in milliseconds.
	ENConnectMs *int           `json:"en_connect_ms,omitempty"` // time to connect to the enforcement node
	AppOpenMs   map[string]int `json:"app_open_ms,omitempty"`   // median time to open a session, per app
	// ClockSkewSec is how far this device's clock is ahead of the control plane's (negative: behind), as
	// the agent saw it in the Date header of the control plane's answers; nil when it has not seen one (GAP-REQ-06).
	ClockSkewSec *int `json:"clock_skew_sec,omitempty"`
	// Path stages (DEX-002, basic): Wi-Fi signal, router, name resolution and an optional anchor.
	pathprobe.Result
}

func pct(n int) *int {
	if n < 0 {
		n = 0
	}
	if n > 999 {
		n = 999
	}
	return &n
}

// Collect measures this machine. Failures leave the field unknown.
func Collect() Snapshot {
	var s Snapshot
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if l, err := strconv.ParseFloat(f[0], 64); err == nil {
				if n := cores(); n > 0 {
					s.CPULoadPct = pct(int(l / float64(n) * 100))
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, avail, ok := ParseMeminfo(string(b)); ok && total > 0 {
			s.MemUsedPct = pct(int(100 * (total - avail) / total))
		}
	}
	dir, _ := os.UserHomeDir()
	if dir == "" {
		dir = "/"
	}
	if used, ok := diskUsedPercent(dir); ok {
		s.DiskUsedPct = pct(used)
	}
	return s
}

func cores() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\nprocessor") + btoi(strings.HasPrefix(string(b), "processor"))
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ParseMeminfo reads /proc/meminfo text and returns total and available kilobytes.
func ParseMeminfo(text string) (total, avail int64, ok bool) {
	var t, a int64
	var gt, ga bool
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			t, gt = v, true
		case "MemAvailable:":
			a, ga = v, true
		}
	}
	return t, a, gt && ga
}

type Entry struct {
	Tenant, User, Device string
	At                   time.Time
	Snapshot
}

type Store struct {
	mu sync.Mutex
	m  map[string]Entry // tenant|device
}

func New() *Store { return &Store{m: map[string]Entry{}} }

func (s *Store) Put(e Entry) {
	s.mu.Lock()
	s.m[e.Tenant+"|"+e.Device] = e
	s.mu.Unlock()
}

// Finding is one thing worth telling an admin.
type Finding struct {
	Device  string `json:"device"`
	User    string `json:"user"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

type Device struct {
	Device   string    `json:"device"`
	User     string    `json:"user"`
	Reported time.Time `json:"reported"`
	Stale    bool      `json:"stale"` // no report for more than 15 minutes
	Snapshot
	Findings   []Finding  `json:"findings"`
	Experience Experience `json:"experience"`
}

// List returns a tenant's devices with findings. now is injectable for tests.
func (s *Store) List(tenant string, now time.Time) []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Device{}
	for _, e := range s.m {
		if e.Tenant != tenant {
			continue
		}
		d := Device{Device: e.Device, User: e.User, Reported: e.At, Snapshot: e.Snapshot, Stale: now.Sub(e.At) > 15*time.Minute, Findings: []Finding{}}
		d.Findings = Findings(e)
		d.Experience = Score(e)
		out = append(out, d)
	}
	sortDevices(out)
	return out
}

// Findings applies fixed thresholds: disk over 90 percent, memory over 90, load over 150.
func Findings(e Entry) []Finding {
	var f []Finding
	if v := e.ClockSkewSec; v != nil && clockhint.Wrong(time.Duration(*v)*time.Second) {
		dir := "ahead of"
		if *v < 0 {
			dir = "behind"
		}
		f = append(f, Finding{e.Device, e.User, fmt.Sprintf("%s's device clock is about %s %s the real time", e.User, clockhint.Span(time.Duration(abs(*v))*time.Second), dir), "Ask them to turn on automatic date and time. With a clock this far off, certificates, approvals and time-based rules stop working and the device may fail to connect at all."})
	}
	if v := e.DiskUsedPct; v != nil && *v >= 90 {
		f = append(f, Finding{e.Device, e.User, fmt.Sprintf("%s's disk is %d%% full", e.User, *v), "Ask them to free space. A full disk breaks updates and can stop disk encryption and logging tools working properly."})
	}
	if v := e.MemUsedPct; v != nil && *v >= 90 {
		f = append(f, Finding{e.Device, e.User, fmt.Sprintf("%s's device is using %d%% of its memory", e.User, *v), "Ask them to restart it or close heavy programs. If it keeps happening the device may need more memory."})
	}
	if v := e.CPULoadPct; v != nil && *v >= 150 {
		f = append(f, Finding{e.Device, e.User, fmt.Sprintf("%s's device is overloaded (load %d%% of capacity)", e.User, *v), "Slow apps here are likely the device, not the network or the app. Check what is running."})
	}
	return f
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func sortDevices(d []Device) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j].Device < d[j-1].Device; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

// Experience is a 0 to 100 score for how usable this device's access feels, and the part of
// the path most to blame when it is low (DEX-001, and the cause split of DEX-002; there are
// no hop-by-hop probes). Fixed thresholds, no model.
type Experience struct {
	Score   int    `json:"score"`
	Cause   string `json:"cause"`   // "none", "device", "network" or "app"
	Explain string `json:"explain"` // one plain sentence
	Known   bool   `json:"known"`   // false when the agent has not reported enough to judge
}

// Score applies the thresholds. Missing measurements are not treated as bad.
func Score(e Entry) Experience {
	var dev, net, app int
	var appName string
	if v := e.CPULoadPct; v != nil && *v >= 150 {
		dev += 30
	}
	if v := e.MemUsedPct; v != nil && *v >= 90 {
		dev += 20
	}
	if v := e.DiskUsedPct; v != nil && *v >= 95 {
		dev += 10
	}
	switch v := e.ENConnectMs; {
	case v == nil:
	case *v > 300:
		net = 40
	case *v > 150:
		net = 20
	case *v > 80:
		net = 10
	}
	names := make([]string, 0, len(e.AppOpenMs))
	for n := range e.AppOpenMs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := 0
		switch ms := e.AppOpenMs[n]; {
		case ms > 2000:
			p = 25
		case ms > 800:
			p = 10
		}
		if p > app {
			app, appName = p, n
		}
	}
	known := e.CPULoadPct != nil || e.MemUsedPct != nil || e.ENConnectMs != nil || len(e.AppOpenMs) > 0
	netCause, netExplain := networkStage(e)
	x := Experience{Score: 100 - dev - net - app, Cause: "none", Known: known}
	if x.Score < 0 {
		x.Score = 0
	}
	switch {
	case !known:
		x.Explain = "No measurements from this device yet."
	case dev == 0 && net == 0 && app == 0:
		x.Explain = "Nothing slow was measured."
	case dev >= net && dev >= app:
		x.Cause, x.Explain = "device", fmt.Sprintf("%s's device is the likely cause: it is overloaded or short of memory or disk.", e.User)
	case net >= app:
		x.Cause, x.Explain = netCause, netExplain
	default:
		x.Cause, x.Explain = "app", fmt.Sprintf("Opening %s takes %d ms while the connection and device look fine: the app or its connector is the likely cause.", appName, e.AppOpenMs[appName])
	}
	return x
}

// networkStage says which stage of the path to the enforcement node is most likely slow, using
// the stage measurements when the agent sent them. Without them it can only say "network".
// Stages are tested from the device outwards, so the first one that looks bad is named.
func networkStage(e Entry) (cause, explain string) {
	slowBy := ""
	if e.ENConnectMs != nil {
		slowBy = fmt.Sprintf(" (%d ms to the enforcement node)", *e.ENConnectMs)
	}
	switch {
	case e.WifiSignalPct != nil && *e.WifiSignalPct < 40:
		return "wifi", fmt.Sprintf("%s's Wi-Fi signal is weak (%d%%)%s: move closer to the access point or use a cable.", e.User, *e.WifiSignalPct, slowBy)
	case e.GatewayMs != nil && *e.GatewayMs > 100:
		return "local-network", fmt.Sprintf("%s's own router is slow to answer (%d ms)%s: the office network is congested or the router is struggling.", e.User, *e.GatewayMs, slowBy)
	case e.DNSMs != nil && *e.DNSMs > 500:
		return "dns", fmt.Sprintf("Looking up the enforcement node's name takes %d ms for %s%s: the DNS resolver is slow.", *e.DNSMs, e.User, slowBy)
	case e.AnchorMs != nil && *e.AnchorMs > 150:
		return "isp", fmt.Sprintf("%s's internet is slow to a neutral site as well (%d ms)%s: the internet provider is the likely cause.", e.User, *e.AnchorMs, slowBy)
	case e.AnchorMs != nil:
		return "cloud", fmt.Sprintf("%s's internet is fast to a neutral site (%d ms) but slow to the enforcement node%s: the path to the node, or the node, is the likely cause.", e.User, *e.AnchorMs, slowBy)
	}
	return "network", fmt.Sprintf("%s's connection to the enforcement node is slow%s: look at their Wi-Fi or internet. (No stage measurements: set an anchor for the agent to tell the internet provider from the node.)", e.User, slowBy)
}

// Erase removes the health reports of a person's devices and returns how many it removed.
func (s *Store) Erase(tenant string, ids []string) int {
	set := map[string]bool{}
	for _, id := range ids {
		set[strings.ToLower(id)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.m {
		if e.Tenant == tenant && set[strings.ToLower(e.User)] {
			delete(s.m, k)
			n++
		}
	}
	return n
}
