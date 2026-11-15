//go:build windows

package devhealth

import (
	"syscall"
	"unsafe"
)

// diskUsedPercent is how full the volume holding dir is, in percent. It asks Windows for the free and total
// bytes available to the user. Written without the ability to run it on Windows here: it is compiled for
// Windows by the release build and has not been executed there by this project's tests.
func diskUsedPercent(dir string) (int, bool) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	var freeToCaller, total, free uint64
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&freeToCaller)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r == 0 || total == 0 {
		return 0, false
	}
	return int(100 * (total - freeToCaller) / total), true
}
