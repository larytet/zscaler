// Package privacy implements the log privacy mode (NFR-033, ADM-006b): when a tenant turns it on, the
// decision records the platform stores, streams and shows carry a stable pseudonym instead of the
// person's name. The pseudonym is a keyed hash, so the same person always gets the same one (a log can
// still be followed) and nobody can work backwards from it without the key; an owner can look a
// pseudonym up, and every look-up is audited. Paths and query strings are never in the records at all.
package privacy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

// Config is a tenant's setting. Key is secret and never returned by an API.
type Config struct {
	PseudonymiseUsers bool      `json:"pseudonymise_users"`
	Key               string    `json:"key,omitempty"` // hex, 32 bytes, made when the mode is first turned on
	Since             time.Time `json:"since,omitempty"`
}

// NewKey makes a key.
func NewKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var pseudo = regexp.MustCompile(`^u-[0-9a-f]{12}$`)

// IsPseudonym reports whether s has the form of a pseudonym.
func IsPseudonym(s string) bool { return pseudo.MatchString(s) }

// Pseudonym returns the pseudonym of a user under a key. AI agents ("agent:name") are not people and
// keep their names.
func Pseudonym(key, user string) string {
	if user == "" || strings.HasPrefix(user, "agent:") || IsPseudonym(user) {
		return user
	}
	k, err := hex.DecodeString(key)
	if err != nil || len(k) == 0 {
		return "u-000000000000" // no usable key: never fall back to the name
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(strings.ToLower(user)))
	return "u-" + hex.EncodeToString(m.Sum(nil))[:12]
}
