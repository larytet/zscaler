// Package versions says whether a component's version can work with the control plane's (GAP-REQ-08).
//
// The rule is one sentence: a component may be at most one minor version older than the control plane, and
// never newer. So the order of an upgrade is the control plane first, then enforcement nodes, then
// connectors, then agents, and a small business can stop half way for as long as it likes inside that
// window. The rule is a policy this product states and tests; it is not enforced by the wire protocol, which
// has no version negotiation.
package versions

import (
	"strconv"
	"strings"
)

// Header is the request header every component sends so that the control plane can list who runs what.
const Header = "X-Ztx-Version"

// Ver is major.minor.patch.
type Ver struct{ Major, Minor, Patch int }

// Parse reads "1.2.3", "v1.2.3", "1.2.3-dev" and "1.2.3+build". A build from the source tree ("dev"), an
// empty string or anything else that does not start with major.minor is not a version.
func Parse(s string) (Ver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Ver{}, false
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 1<<20 {
			return Ver{}, false
		}
		n[i] = v
	}
	return Ver{n[0], n[1], n[2]}, true
}

// Status words.
const (
	Current = "current"    // same major and minor as the control plane
	Behind  = "one-behind" // exactly one minor version older: supported, upgrade soon
	TooOld  = "too-old"    // two or more minor versions (or a major version) behind: not supported
	Newer   = "newer"      // ahead of the control plane: upgrade the control plane first
	Unknown = "unknown"    // not a version (a source-tree build) or not reported
)

// Classify compares a component with the control plane and says what to do about it.
func Classify(controlPlane, component string) (status, message string) {
	cp, ok1 := Parse(controlPlane)
	c, ok2 := Parse(component)
	switch {
	case !ok2 && strings.TrimSpace(component) == "":
		return Unknown, "has not reported a version"
	case !ok2:
		return Unknown, "runs a build that is not a release (" + strings.TrimSpace(component) + "), so its age cannot be judged"
	case !ok1:
		return Unknown, "the control plane runs a build that is not a release, so skew cannot be judged"
	case c.Major > cp.Major || (c.Major == cp.Major && c.Minor > cp.Minor):
		return Newer, "is newer than the control plane: upgrade the control plane first"
	case c.Major < cp.Major:
		return TooOld, "is a major version behind the control plane: not supported, upgrade it"
	case c.Minor == cp.Minor:
		return Current, ""
	case cp.Minor-c.Minor == 1:
		return Behind, "is one minor version behind the control plane: supported, upgrade it soon"
	default:
		return TooOld, "is more than one minor version behind the control plane: not supported, upgrade it"
	}
}
