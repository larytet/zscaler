package dlp

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

// Exact data match (DATA-006). An organisation gives the platform a list of values it must not
// lose (customer numbers, e-mail addresses, account IDs). Only salted hashes are kept; a request or
// response that contains any of the values is reported as the type "edm:<set name>".
//
// Limits, stated plainly: a value is a single token of letters, digits and . _ @ + - (4 to 64
// characters), so names with spaces are not matched; matching is case-insensitive; and a hash of a
// guessable value (a phone number, a short ID) can be guessed by whoever holds the hashes.

const (
	EDMPrefix    = "edm:"
	EDMMaxValues = 10000
	edmMinLen    = 4
	edmMaxLen    = 64
)

var edmName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidEDMName reports whether name can name a data set.
func ValidEDMName(name string) bool { return edmName.MatchString(name) }

// KnownType is Known, plus "edm:<name>" for a well-formed set name. Whether the set exists is
// checked where the policy is saved.
func KnownType(name string) bool {
	if strings.HasPrefix(name, EDMPrefix) {
		return ValidEDMName(strings.TrimPrefix(name, EDMPrefix))
	}
	return Known(name)
}

type edmKey [16]byte

// EDM is one compiled data set.
type EDM struct {
	salt []byte
	set  map[edmKey]struct{}
}

func isTokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '@' || c == '+' || c == '-'
}

func edmHash(salt []byte, tok []byte) edmKey {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(strings.ToLower(string(tok))))
	var k edmKey
	copy(k[:], h.Sum(nil))
	return k
}

// Normalise returns the value as it will be hashed, or false if it cannot be matched.
func Normalise(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < edmMinLen || len(v) > edmMaxLen {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		if !isTokenByte(v[i]) {
			return "", false
		}
	}
	return strings.ToLower(v), true
}

// Hash returns the stored form of a value (hex, 32 characters) for the given salt.
func Hash(salt []byte, v string) (string, bool) {
	n, ok := Normalise(v)
	if !ok {
		return "", false
	}
	k := edmHash(salt, []byte(n))
	return encodeKey(k), true
}

const hexd = "0123456789abcdef"

func encodeKey(k edmKey) string {
	b := make([]byte, 32)
	for i, c := range k {
		b[2*i], b[2*i+1] = hexd[c>>4], hexd[c&15]
	}
	return string(b)
}

func decodeKey(s string) (k edmKey, ok bool) {
	if len(s) != 32 {
		return k, false
	}
	for i := 0; i < 16; i++ {
		hi, lo := unhex(s[2*i]), unhex(s[2*i+1])
		if hi < 0 || lo < 0 {
			return k, false
		}
		k[i] = byte(hi<<4 | lo)
	}
	return k, true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// NewEDM compiles stored hashes (as made by Hash with the same salt).
func NewEDM(salt []byte, hashes []string) *EDM {
	e := &EDM{salt: salt, set: make(map[edmKey]struct{}, len(hashes))}
	for _, h := range hashes {
		if k, ok := decodeKey(h); ok {
			e.set[k] = struct{}{}
		}
	}
	return e
}

// Found reports whether body contains any value of the set.
func (e *EDM) Found(body []byte) bool {
	if e == nil || len(e.set) == 0 {
		return false
	}
	i := 0
	for i < len(body) {
		for i < len(body) && !isTokenByte(body[i]) {
			i++
		}
		j := i
		for j < len(body) && isTokenByte(body[j]) {
			j++
		}
		if n := j - i; n >= edmMinLen && n <= edmMaxLen {
			if _, ok := e.set[edmHash(e.salt, body[i:j])]; ok {
				return true
			}
		}
		// punctuation that ends a sentence or joins a list is not part of the value
		lo, hi := i, j
		for lo < hi && strings.IndexByte(".-_+", body[lo]) >= 0 {
			lo++
		}
		for hi > lo && strings.IndexByte(".-_+", body[hi-1]) >= 0 {
			hi--
		}
		if (lo != i || hi != j) && hi-lo >= edmMinLen && hi-lo <= edmMaxLen {
			if _, ok := e.set[edmHash(e.salt, body[lo:hi])]; ok {
				return true
			}
		}
		i = j
	}
	return false
}

// ScanWith is Scan plus every data set, reporting the sets that matched as "edm:<name>".
func ScanWith(body []byte, sets map[string]*EDM) []string {
	hits := Scan(body)
	if len(sets) == 0 {
		return hits
	}
	for name, e := range sets {
		if e.Found(body) {
			hits = append(hits, EDMPrefix+name)
		}
	}
	sortStrings(hits)
	return hits
}
