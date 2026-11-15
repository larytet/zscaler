package webproxy

import "testing"

func TestManagedExemptionsAreNotDecryptedAndCanBeOverridden(t *testing.T) { // AGT-032 (ZIA-032)
	r := newRig(t)
	r.proxy.Classifier = NewClassifier(map[string][]string{"banking": {"bank.example"}, "health": {"clinic.example"}, "gambling": {"bets.example"}})
	enableInspection(r, "mine.example")
	decrypted := func(host string) bool { return r.proxy.interceptCA("t1", host) != nil }

	// by default: the organisation's own list, the pinned applications, and banking and health sites
	r.st.set(func(s *state) { s.exemptCats = []string{"banking", "health"} })
	for host, want := range map[string]bool{
		"mine.example": false, "sub.mine.example": false, // the organisation's own exemption
		"api.icloud.com": false, "download.windowsupdate.com": false, // pinned applications
		"login.bank.example": false, "bank.example": false, "portal.clinic.example": false, // banking and health, by the category list
		"bets.example": true, "news.example": true, "icloud.com.evil.example": true, // everything else is decrypted, look-alikes included
	} {
		if got := decrypted(host); got != want {
			t.Errorf("%s decrypted = %v, want %v", host, got, want)
		}
	}
	// override: the built-in list off, the categories changed or emptied
	r.st.set(func(s *state) { s.managedOff = true })
	if !decrypted("api.icloud.com") {
		t.Error("with the built-in list off a pinned application is decrypted")
	}
	if decrypted("bank.example") {
		t.Error("the category exemption is separate from the built-in list")
	}
	r.st.set(func(s *state) { s.exemptCats = []string{} })
	if !decrypted("bank.example") || !decrypted("clinic.example") {
		t.Error("with no exempt categories banking and health are decrypted")
	}
	if decrypted("mine.example") {
		t.Error("the organisation's own list always applies")
	}
	r.st.set(func(s *state) { s.exemptCats = []string{"gambling"} })
	if decrypted("bets.example") || !decrypted("bank.example") {
		t.Error("the categories are the organisation's choice")
	}
	// inspection off: nothing is decrypted, whatever the lists say
	r.st.set(func(s *state) { s.enabled = false })
	if decrypted("news.example") {
		t.Error("with inspection off nothing is decrypted")
	}
}
