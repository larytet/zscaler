package agent

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/posture"
)

// Probes are the commands used to collect posture. They are injectable so
// tests do not run real system commands.
type Probes struct {
	OS      string
	Version func() string
	Run     func(name string, args ...string) (string, error)
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func DefaultProbes() Probes {
	return Probes{OS: runtime.GOOS, Run: run, Version: func() string {
		switch runtime.GOOS {
		case "linux":
			out, _ := run("uname", "-r")
			return strings.TrimSpace(out)
		case "darwin":
			out, _ := run("sw_vers", "-productVersion")
			return strings.TrimSpace(out)
		case "windows":
			out, _ := run("cmd", "/c", "ver")
			return strings.TrimSpace(out)
		}
		return ""
	}}
}

// Collect builds a report. Any probe that fails or is unrecognised yields
// unknown (nil), which policy treats as failing.
func Collect(p Probes) posture.Report {
	r := posture.Report{OS: p.OS}
	if p.Version != nil {
		r.OSVersion = p.Version()
	}
	out := func(name string, args ...string) string {
		s, err := p.Run(name, args...)
		if err != nil && s == "" {
			return ""
		}
		return s
	}
	switch p.OS {
	case "darwin":
		r.DiskEncrypted = posture.ParseFdesetup(out("fdesetup", "status"))
		r.FirewallOn = posture.ParseSocketFilter(out("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"))
	case "windows":
		r.DiskEncrypted = posture.ParseManageBde(out("manage-bde", "-status", "C:"))
		// firewall probe for Windows is not implemented in RB1: stays unknown
	case "linux":
		r.DiskEncrypted = posture.ParseLsblkCrypt(out("lsblk", "-n", "-o", "TYPE"))
		r.FirewallOn = posture.ParseUFW(out("ufw", "status"))
		r.RemovableMedia = posture.ParseLsblkRemovable(out("lsblk", "-l", "-n", "-o", "RM,MOUNTPOINT"))
	}
	return r
}
