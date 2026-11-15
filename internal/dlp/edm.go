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
	doc  bool // a document set: matched by runs of words, not by single tokens
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
	if e.doc {
		return e.foundDoc(body)
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

// Index document match (DATA-006, second part). An organisation gives the platform documents it
// must not lose (a price list, a contract template, source files). Each is cut into overlapping
// runs of eight words; only salted hashes of the runs are kept. A request or response that
// repeats at least DocMinRuns of those runs is reported like a value match.
//
// Limits: only text (the platform cannot read PDF or Word files, the admin pastes the text);
// copying that changes more than one word in every eight, or pasting only a short excerpt, is
// not found; matching is case-insensitive and ignores punctuation.

const (
	DocWords      = 8
	DocMinRuns    = 3     // distinct matching runs needed to call it a copy (about ten words in a row)
	DocMaxRuns    = 50000 // per data set
	DocMaxSources = 20
)

// words splits text into lower-case alphanumeric words.
func words(b []byte) [][]byte {
	var out [][]byte
	i := 0
	for i < len(b) {
		for i < len(b) && !isAlnum(b[i]) {
			i++
		}
		j := i
		for j < len(b) && isAlnum(b[j]) {
			j++
		}
		if j > i {
			w := make([]byte, j-i)
			for k := range w {
				c := b[i+k]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				w[k] = c
			}
			out = append(out, w)
		}
		i = j
	}
	return out
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

func runKey(salt []byte, ws [][]byte) edmKey {
	h := sha256.New()
	h.Write(salt)
	for i, w := range ws {
		if i > 0 {
			h.Write([]byte{' '})
		}
		h.Write(w)
	}
	var k edmKey
	copy(k[:], h.Sum(nil))
	return k
}

// DocRuns returns the distinct hashed runs of a document (hex), or none if it is shorter than
// DocWords words.
func DocRuns(salt []byte, text string) []string {
	ws := words([]byte(text))
	seen := map[edmKey]bool{}
	var out []string
	for i := 0; i+DocWords <= len(ws); i++ {
		k := runKey(salt, ws[i:i+DocWords])
		if !seen[k] {
			seen[k] = true
			out = append(out, encodeKey(k))
		}
	}
	return out
}

// NewDocSet compiles stored runs into a set that matches copies of the documents.
func NewDocSet(salt []byte, runs []string) *EDM {
	e := NewEDM(salt, runs)
	e.doc = true
	return e
}

func (e *EDM) foundDoc(body []byte) bool {
	ws := words(body)
	hits := map[edmKey]bool{}
	for i := 0; i+DocWords <= len(ws); i++ {
		k := runKey(e.salt, ws[i:i+DocWords])
		if _, ok := e.set[k]; ok {
			hits[k] = true
			if len(hits) >= DocMinRuns {
				return true
			}
		}
	}
	return false
}
