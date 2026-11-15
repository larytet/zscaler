package exemptions

import "testing"

func TestPinnedAndCategoryMatching(t *testing.T) { // AGT-032 (ZIA-032)
	for _, h := range []string{"icloud.com", "api.icloud.com", "WWW.Apple.COM.", "windowsupdate.com", "download.windowsupdate.com", "signal.org"} {
		if !IsPinned(h) {
			t.Errorf("%s should be exempt", h)
		}
	}
	// look-alikes and unrelated hosts are not exempt: nobody gets out of inspection by choosing a name
	for _, h := range []string{"icloud.com.evil.example", "notapple.com", "evil-icloud.com", "example.com", "", "apple.com.attacker.net"} {
		if IsPinned(h) {
			t.Errorf("%q must not be exempt", h)
		}
	}
	if !CategoryExempt([]string{"news", "banking"}, DefaultCategories) || CategoryExempt([]string{"news"}, DefaultCategories) || CategoryExempt(nil, DefaultCategories) || CategoryExempt([]string{"banking"}, nil) {
		t.Fatal("CategoryExempt")
	}
	if len(DefaultCategories) != 2 || DefaultCategories[0] != "banking" || DefaultCategories[1] != "health" {
		t.Fatalf("%v", DefaultCategories)
	}
}
