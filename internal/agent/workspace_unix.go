//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// The browser starts several processes; they are killed together.
func setProcessGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killProcessGroup(c *exec.Cmd) {
	if c.Process != nil {
		syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}
}
