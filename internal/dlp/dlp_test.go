package dlp

import (
	"strings"
	"testing"
	"time"
)

func has(t *testing.T, body, name string) bool {
	t.Helper()
	for _, h := range Scan([]byte(body)) {
		if h == name {
			return true
		}
	}
	return false
}

func TestCreditCards(t *testing.T) {
	for _, ok := range []string{
		"card=4111111111111111", "pay 4111 1111 1111 1111 now", "4111-1111-1111-1111",
		"5555555555554444", "378282246310005", `{"number":"4012888888881881"}`,
	} {
		if !has(t, ok, CreditCard) {
			t.Errorf("missed a valid card number in %q", ok)
		}
	}
	for _, no := range []string{
		"4111111111111112",     // fails Luhn
		"1234567890123456",     // fails Luhn
		"0000000000000000",     // passes Luhn but is not a card
		"1111111111111111",     // repeated digit
		"order 20261115123456", // 14 digits, fails Luhn
		"phone +1 415 555 0132",
		"1234",
	} {
		if has(t, no, CreditCard) {
			t.Errorf("false positive for a card in %q", no)
		}
	}
}

func TestSSN(t *testing.T) {
	if !has(t, "ssn: 123-45-6789", USSSN) {
		t.Fatal("missed a valid SSN")
	}
	for _, no := range []string{"000-12-3456", "666-12-3456", "912-34-5678", "123-00-4567", "123-45-0000", "1234-56-7890", "12-345-6789"} {
		if has(t, no, USSSN) {
			t.Errorf("never-issued or malformed number flagged: %q", no)
		}
	}
}

func TestIBAN(t *testing.T) {
	for _, ok := range []string{"GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00", "iban=FR1420041010050500013M02606"} {
		if !has(t, ok, IBAN) {
			t.Errorf("missed %q", ok)
		}
	}
	for _, no := range []string{"GB82WEST12345698765433", "DE89 3704 0044 0532 0130 01", "AB12 hello world", "ZZ00"} {
		if has(t, no, IBAN) {
			t.Errorf("false positive %q", no)
		}
	}
}

func TestSecrets(t *testing.T) {
	if !has(t, "key AKIAIOSFODNN7EXAMPLE here", AWSKey) || !has(t, "ASIAIOSFODNN7EXAMPLE", AWSKey) {
		t.Fatal("AWS key")
	}
	if has(t, "AKIAshort", AWSKey) || has(t, "xAKIAIOSFODNN7EXAMPLEx", AWSKey) {
		t.Fatal("AWS false positive")
	}
	if !has(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", PrivateKey) || !has(t, "-----BEGIN PRIVATE KEY-----", PrivateKey) || !has(t, "-----BEGIN EC PRIVATE KEY-----", PrivateKey) {
		t.Fatal("private key")
	}
	if has(t, "-----BEGIN CERTIFICATE-----", PrivateKey) || has(t, "-----BEGIN PUBLIC KEY-----", PrivateKey) {
		t.Fatal("a certificate or public key is not a secret")
	}
	if !has(t, "token=ghp_"+strings.Repeat("a1B2", 9), GitHubToken) {
		t.Fatal("github token")
	}
	if has(t, "ghp_tooshort", GitHubToken) {
		t.Fatal("github false positive")
	}
}

func TestScanReturnsNamesOnlyAndSorted(t *testing.T) {
	hits := Scan([]byte("ssn 123-45-6789 card 4111111111111111 key AKIAIOSFODNN7EXAMPLE"))
	if strings.Join(hits, ",") != "aws-access-key,credit-card,us-ssn" {
		t.Fatalf("%v", hits)
	}
	for _, h := range hits {
		if strings.ContainsAny(h, "0123456789") && h != "us-ssn" && h != "iban" {
			t.Fatalf("a finding must be a type name, not data: %q", h)
		}
	}
	if len(Scan([]byte("an ordinary sentence with the number 42 and a date 2026-11-15"))) != 0 {
		t.Fatal("ordinary text flagged")
	}
	if len(Scan(nil)) != 0 {
		t.Fatal("nil body")
	}
}

func TestNamesAndKnown(t *testing.T) {
	if len(Names()) != 6 || !Known(CreditCard) || Known("made-up") {
		t.Fatal(Names())
	}
}

func BenchmarkScan1MiB(b *testing.B) {
	body := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog 12345 67890. ", 18000))
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		Scan(body)
	}
}

func FuzzScan(f *testing.F) {
	f.Add([]byte("4111111111111111 123-45-6789 GB82WEST12345698765432"))
	f.Add([]byte("AB12 CD34 EF56 GH78 IJ90 KL12 MN34 OP56 QR78 ST90 UV12"))
	f.Add([]byte("1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6"))
	f.Fuzz(func(t *testing.T, b []byte) { Scan(b) })
}

// Bodies are attacker-controlled, so the worst case matters more than the average.
func TestAdversarialInputsStayFast(t *testing.T) {
	const mib = 1 << 20
	cases := map[string][]byte{
		"digits":           []byte(strings.Repeat("1234567890", mib/10)),
		"spaced digits":    []byte(strings.Repeat("1 2 3 4 5 6 7 8 ", mib/16)),
		"dashed digits":    []byte(strings.Repeat("123-45-678", mib/10)),
		"iban lookalikes":  []byte(strings.Repeat("AB12 ", mib/5)),
		"iban long":        []byte(strings.Repeat("GB82WEST1234569876543", mib/21)),
		"capitals":         []byte(strings.Repeat("A", mib)),
		"key prefix":       []byte(strings.Repeat("-----BEGIN ", mib/11)),
		"aws prefix":       []byte(strings.Repeat("AKIA", mib/4)),
		"gh prefix":        []byte(strings.Repeat("ghp_", mib/4)),
		"nul bytes":        make([]byte, mib),
		"card-like groups": []byte(strings.Repeat("4111 1111 1111 111 ", mib/19)),
	}
	for name, body := range cases {
		start := time.Now()
		Scan(body)
		if d := time.Since(start); d > 2*time.Second*raceSlowdown {
			t.Errorf("%s: scanning 1 MiB took %v", name, d)
		} else {
			t.Logf("%-16s %v", name, d.Round(time.Millisecond))
		}
	}
}
