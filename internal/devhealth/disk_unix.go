//go:build !windows

package devhealth

import "syscall"

// diskUsedPercent is how full the volume holding dir is, in percent.
func diskUsedPercent(dir string) (int, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil || st.Blocks == 0 {
		return 0, false
	}
	return int(100 * (st.Blocks - st.Bavail) / st.Blocks), true
}
