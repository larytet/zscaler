//go:build windows

package agent

import "os/exec"

func setProcessGroup(c *exec.Cmd) {}

func killProcessGroup(c *exec.Cmd) {
	if c.Process != nil {
		c.Process.Kill()
	}
}
