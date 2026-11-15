// Package dlp finds sensitive data in decrypted request bodies (DATA-001, in
// basic form). Detectors are pattern based and validated where a checksum
// exists, to keep false positives down. There is no exact data match, OCR or
// machine learning. A finding is a data-type name: matched text is never
// returned, stored or logged.
package dlp

import (
	"bytes"
	"regexp"
	"sort"
)

// Detector names, usable in policy rules.
const (
	CreditCard  = "credit-card"
	USSSN       = "us-ssn"
	IBAN        = "iban"
	AWSKey      = "aws-access-key"
	PrivateKey  = "private-key"
	GitHubToken = "github-token"
)

var detectors = map[string]func([]byte) bool{
	CreditCard: hasCard,
	USSSN:      hasSSN,
	IBAN:       hasIBAN,
	AWSKey: func(b []byte) bool {
		return (bytes.Contains(b, []byte("AKIA")) || bytes.Contains(b, []byte("ASIA"))) && awsRe.Match(b)
	},
	PrivateKey: func(b []byte) bool { return bytes.Contains(b, []byte("PRIVATE KEY-----")) && keyRe.Match(b) },
	GitHubToken: func(b []byte) bool {
		return bytes.Contains(b, []byte("gh")) && bytes.Contains(b, []byte("_")) && ghRe.Match(b)
	},
}

// Names lists the available detectors.
func Names() []string {
	out := make([]string, 0, len(detectors))
	for n := range detectors {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Known reports whether name is a detector.
func Known(name string) bool { _, ok := detectors[name]; return ok }

// Scan returns the names of the detectors that fired, sorted.
func Scan(body []byte) []string {
	var hits []string
	for name, f := range detectors {
		if f(body) {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	return hits
}

var (
	awsRe = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	keyRe = regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----`)
	ghRe  = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)
)

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// hasCard walks the body once. A candidate is a run of digits that may be split by single
// spaces or dashes, standing alone (not glued to letters or more digits).
func hasCard(b []byte) bool {
	n := len(b)
	for i := 0; i < n; {
		if !isDigit(b[i]) || (i > 0 && isWord(b[i-1])) {
			i++
			continue
		}
		var digits [24]byte
		cnt, j, last := 0, i, i
		for j < n {
			c := b[j]
			if isDigit(c) {
				if cnt < len(digits) {
					digits[cnt] = c
				}
				cnt++
				last = j
				j++
			} else if (c == ' ' || c == '-') && j+1 < n && isDigit(b[j+1]) && cnt > 0 {
				j++
			} else {
				break
			}
		}
		end := last + 1
		if cnt >= 13 && cnt <= 19 && (end >= n || !isWord(b[end])) && luhn(digits[:cnt]) && plausibleIssuer(digits[:cnt]) {
			return true
		}
		i = j
		if i == end { // the run ended on a non-digit: move on
			i++
		}
	}
	return false
}

func luhn(d []byte) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// plausibleIssuer rejects runs such as all zeros or a repeated digit that happen to pass Luhn.
func plausibleIssuer(d []byte) bool {
	same := true
	for _, c := range d {
		if c != d[0] {
			same = false
		}
	}
	return !same && d[0] != '0'
}

func hasSSN(b []byte) bool {
	for i := 0; i+11 <= len(b); i++ {
		if b[i+3] != '-' || b[i+6] != '-' || !isDigit(b[i]) || (i > 0 && isWord(b[i-1])) {
			continue
		}
		ok := true
		for _, k := range [...]int{0, 1, 2, 4, 5, 7, 8, 9, 10} {
			if !isDigit(b[i+k]) {
				ok = false
				break
			}
		}
		if !ok || (i+11 < len(b) && isWord(b[i+11])) {
			continue
		}
		area, group, serial := string(b[i:i+3]), string(b[i+4:i+6]), string(b[i+7:i+11])
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			continue // never issued
		}
		return true
	}
	return false
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

// hasIBAN looks for two capitals and two digits at a word start. An IBAN is either one
// unbroken run of letters and digits, or groups of four separated by single spaces with a
// shorter last group. Only those shapes are tested with the mod-97 check, which keeps the
// work per position small even for hostile input.
func hasIBAN(b []byte) bool {
	for i := 0; i+15 <= len(b); i++ {
		if !isUpper(b[i]) || !isUpper(b[i+1]) || !isDigit(b[i+2]) || !isDigit(b[i+3]) || (i > 0 && isWord(b[i-1])) {
			continue
		}
		// shape 1: one unbroken run
		j := i
		for j < len(b) && (isDigit(b[j]) || isUpper(b[j])) {
			j++
		}
		if n := j - i; n >= 15 && n <= 34 && (j >= len(b) || !isWord(b[j])) && ibanValid(b[i:j]) {
			return true
		}
		// shape 2: groups of four
		var s [34]byte
		cnt, p := 0, i
		for g := 0; g < 9 && p < len(b); g++ {
			q := p
			for q < len(b) && q-p < 4 && cnt < len(s) && (isDigit(b[q]) || isUpper(b[q])) {
				s[cnt] = b[q]
				cnt++
				q++
			}
			if q == p {
				break
			}
			full := q-p == 4
			if cnt >= 15 && (q >= len(b) || !isWord(b[q])) && ibanValid(s[:cnt]) {
				return true
			}
			if !full || q >= len(b) || b[q] != ' ' {
				break
			}
			p = q + 1
		}
	}
	return false
}

// ibanValid applies the ISO 13616 mod-97 check.
func ibanValid(s []byte) bool {
	r := append(append([]byte{}, s[4:]...), s[:4]...)
	rem := 0
	for _, c := range r {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
			rem = (rem*10 + v) % 97
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}
