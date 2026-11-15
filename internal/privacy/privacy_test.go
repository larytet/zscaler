package privacy

import (
	"strings"
	"testing"
)

func TestPseudonymsAreStableKeyedAndSafe(t *testing.T) { // AGT-027 (NFR-033, ADM-006b)
	k1, k2 := NewKey(), NewKey()
	if k1 == k2 || len(k1) != 64 {
		t.Fatal("keys must be random 32 bytes")
	}
	a := Pseudonym(k1, "alice@example.com")
	if !IsPseudonym(a) || strings.Contains(a, "alice") {
		t.Fatalf("%s", a)
	}
	if Pseudonym(k1, "alice@example.com") != a || Pseudonym(k1, "ALICE@example.com") != a {
		t.Fatal("the same person must always get the same pseudonym, whatever the case")
	}
	if Pseudonym(k1, "bob@example.com") == a || Pseudonym(k2, "alice@example.com") == a {
		t.Fatal("another person or another tenant's key must give another pseudonym")
	}
	// a pseudonym is not hashed again, and an AI agent is not a person
	if Pseudonym(k1, a) != a || Pseudonym(k1, "agent:helper") != "agent:helper" || Pseudonym(k1, "") != "" {
		t.Fatal("pseudonym rules")
	}
	// a broken key never falls back to the name
	for _, bad := range []string{"", "zz", "not hex at all"} {
		if got := Pseudonym(bad, "alice@example.com"); strings.Contains(got, "alice") || !IsPseudonym(got) {
			t.Fatalf("%q: %s", bad, got)
		}
	}
	for _, s := range []string{"u-abc", "u-ABCDEF012345", "x-0123456789ab", "u-0123456789abc", ""} {
		if IsPseudonym(s) {
			t.Errorf("%q is not a pseudonym", s)
		}
	}
}
