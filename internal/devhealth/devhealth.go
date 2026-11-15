// Package devhealth holds the latest device health numbers (DEX-003, basic) and turns
// them into plain-language findings. The agent measures CPU load, memory and disk on
// Linux; on other systems the fields stay unknown (nil) and nothing is claimed.
package devhealth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Snapshot is what the agent reports. Percentages are 0 to 100; nil means unknown.
type Snapshot struct {
	CPULoadPct  *int `json:"cpu_load_pct,omitempty"`  // 1-minute load average as a percentage of core count
	MemUsedPct  *int `json:"mem_used_pct,omitempty"`  // memory in use, not counting reclaimable cache
	DiskUsedPct *int `json:"disk_used_pct,omitempty"` // the volume holding the home directory
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
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err == nil && st.Blocks > 0 {
		s.DiskUsedPct = pct(int(100 * (st.Blocks - st.Bavail) / st.Blocks))
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
	Findings []Finding `json:"findings"`
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
		out = append(out, d)
	}
	sortDevices(out)
	return out
}

// Findings applies fixed thresholds: disk over 90 percent, memory over 90, load over 150.
func Findings(e Entry) []Finding {
	var f []Finding
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

func sortDevices(d []Device) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j].Device < d[j-1].Device; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}
