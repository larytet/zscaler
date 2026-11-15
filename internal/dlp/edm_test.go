package dlp

import (
	"strings"
	"testing"
)

func mk(t *testing.T, salt string, vals ...string) *EDM {
	var hs []string
	for _, v := range vals {
		h, ok := Hash([]byte(salt), v)
		if !ok {
			t.Fatalf("value %q rejected", v)
		}
		hs = append(hs, h)
	}
	return NewEDM([]byte(salt), hs)
}

func TestEDMFindsExactValuesOnly(t *testing.T) { // AGT-017 (DATA-006)
	e := mk(t, "salt1", "CUST-004711", "jane.doe@example.com", "ACCT99812345")
	for body, want := range map[string]bool{
		`{"customer":"CUST-004711"}`:     true,
		"mail jane.doe@example.com now":  true,
		"mail JANE.DOE@EXAMPLE.COM":      true,
		"acct=ACCT99812345;":             true,
		"CUST-004712":                    false, // one digit off
		"xCUST-004711":                   false, // a longer token is a different value
		"write to jane.doe@example.com.": true,  // sentence end
		"nothing to see":                 false,
		"":                               false,
		strings.Repeat("a", 5000) + " CUST-004711 z": true,
	} {
		if got := e.Found([]byte(body)); got != want {
			t.Errorf("%q: got %v want %v", body[:min(len(body), 40)], got, want)
		}
	}
}

func TestEDMSaltAndRejects(t *testing.T) {
	a, _ := Hash([]byte("s1"), "CUST-004711")
	b, _ := Hash([]byte("s2"), "CUST-004711")
	if a == b || len(a) != 32 {
		t.Fatal("hashes must depend on the salt")
	}
	for _, v := range []string{"abc", "has space inside", "", strings.Repeat("x", 65), "semi;colon"} {
		if _, ok := Hash([]byte("s"), v); ok {
			t.Errorf("%q should be rejected", v)
		}
	}
	if !KnownType("edm:customers") || KnownType("edm:Bad Name") || KnownType("nonsense") || !KnownType(CreditCard) {
		t.Fatal("KnownType")
	}
}

func TestScanWithReportsSets(t *testing.T) {
	e := mk(t, "s", "CUST-004711")
	hits := ScanWith([]byte("CUST-004711 and 4111 1111 1111 1111"), map[string]*EDM{"customers": e})
	if len(hits) != 2 || hits[0] != "credit-card" || hits[1] != "edm:customers" {
		t.Fatalf("%v", hits)
	}
}

func TestEDMSpeed(t *testing.T) {
	var vals []string
	for i := 0; i < 10000; i++ {
		vals = append(vals, "CUST-"+strings.Repeat("0", 3)+itoa(100000+i))
	}
	e := mk(t, "s", vals...)
	body := []byte(strings.Repeat("lorem ipsum dolor sit amet consectetur ", 25000)) // about 1 MB
	if e.Found(body) {
		t.Fatal("false match")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
