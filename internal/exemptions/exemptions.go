// Package exemptions holds the managed part of TLS inspection exemptions (ZIA-032, SMB-022): sites that
// should not be decrypted unless the organisation says otherwise, so inspection does not break
// applications or read what people would rather keep private.
//
// Two things are exempt automatically: sites in the categories the organisation lists (banking and
// health by default), and a built-in list of applications known to refuse an intercepted connection
// because they pin their certificates. The category part works only for sites that the node's category
// list puts in those categories: this platform ships no banking or health list of its own. The built-in
// list below is hand-made, is not exhaustive, and has not been checked against the live services.
package exemptions

import "strings"

// DefaultCategories are the categories exempt unless the organisation chooses others.
var DefaultCategories = []string{"banking", "health"}

// Pinned are applications that are known (to the author, unverified) to fail or misbehave when their
// connection is intercepted. A domain here covers its subdomains.
var Pinned = []string{
	"apple.com", "icloud.com", "mzstatic.com", "apple-dns.net", // Apple devices and services
	"windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", // Windows update
	"whatsapp.com", "whatsapp.net", "signal.org", "telegram.org", // messengers that pin
	"1password.com", "bitwarden.com", "lastpass.com", // password managers
}

// IsPinned reports whether host is one of the built-in pinned-application domains or under one.
func IsPinned(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range Pinned {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// CategoryExempt reports whether any of the site's categories is one the organisation exempts.
func CategoryExempt(siteCategories, exempt []string) bool {
	for _, c := range siteCategories {
		for _, e := range exempt {
			if c == e {
				return true
			}
		}
	}
	return false
}
