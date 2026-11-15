package posture

import "strings"

// Parsers turn the text output of OS commands into tri-state values.
// nil means unknown (unrecognised, localised or empty output): it must never
// be guessed, because policy treats unknown as failing.

func bptr(b bool) *bool { return &b }

// ParseFdesetup reads `fdesetup status` (macOS).
func ParseFdesetup(out string) *bool {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return bptr(true)
	case strings.Contains(out, "FileVault is Off"):
		return bptr(false)
	}
	return nil
}

// ParseManageBde reads `manage-bde -status C:` (Windows).
func ParseManageBde(out string) *bool {
	switch {
	case strings.Contains(out, "Protection Status:    Protection On"),
		strings.Contains(out, "Protection Status: Protection On"):
		return bptr(true)
	case strings.Contains(out, "Protection Off"):
		return bptr(false)
	}
	return nil
}

// ParseUFW reads `ufw status` (Linux).
func ParseUFW(out string) *bool {
	switch {
	case strings.Contains(out, "Status: active"):
		return bptr(true)
	case strings.Contains(out, "Status: inactive"):
		return bptr(false)
	}
	return nil
}

// ParseSocketFilter reads `socketfilterfw --getglobalstate` (macOS).
func ParseSocketFilter(out string) *bool {
	switch {
	case strings.Contains(out, "enabled"):
		return bptr(true)
	case strings.Contains(out, "disabled"):
		return bptr(false)
	}
	return nil
}

// ParseLsblkCrypt reads `lsblk -o TYPE` and reports whether any crypt device
// exists. Empty output is unknown.
func ParseLsblkCrypt(out string) *bool {
	if strings.TrimSpace(out) == "" {
		return nil
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "crypt" {
			return bptr(true)
		}
	}
	return bptr(false)
}

// ParseLsblkRemovable reads `lsblk -l -n -o RM,MOUNTPOINT` (Linux) and reports whether a removable
// drive is mounted. Empty output is unknown.
func ParseLsblkRemovable(out string) *bool {
	if strings.TrimSpace(out) == "" {
		return nil
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "1" {
			return bptr(true)
		}
	}
	return bptr(false)
}
