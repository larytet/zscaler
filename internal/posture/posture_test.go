package posture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func report() Report {
	tr := true
	return Report{DeviceID: "d1", TS: time.Now().UTC().Truncate(time.Second), Nonce: NewNonce(),
		OS: "linux", OSVersion: "6.8", DiskEncrypted: &tr, AgentVersion: "0.1.0"}
}

func TestSignVerify(t *testing.T) { // POS-001
	k := key(t)
	tok, err := Sign(k, report())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Verify(&k.PublicKey, tok)
	if err != nil || r.DeviceID != "d1" || r.DiskEncrypted == nil || !*r.DiskEncrypted || r.FirewallOn != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if p := r.ToPolicy(); p.OS != "linux" || p.FirewallOn != nil {
		t.Fatalf("%+v", p)
	}
}

func TestTamperWrongKeyMalformed(t *testing.T) { // POS-002
	k, other := key(t), key(t)
	tok, _ := Sign(k, report())
	parts := strings.Split(tok, ".")
	tampered := report()
	f := false
	tampered.DiskEncrypted = &f
	other2, _ := Sign(k, tampered)
	forged := parts[0] + "." + strings.Split(other2, ".")[1] + "." + parts[2] // payload swapped, signature kept
	noneHdr := "eyJhbGciOiJub25lIn0"                                          // {"alg":"none"}
	for name, bad := range map[string]string{
		"payload-swapped": forged,
		"wrong-key":       tok, // verified with other's key below
		"alg-none":        noneHdr + "." + parts[1] + ".",
		"two-parts":       parts[0] + "." + parts[1],
		"empty":           "",
		"bad-b64":         "a!.b!.c!",
		"short-sig":       parts[0] + "." + parts[1] + ".AAAA",
	} {
		pub := &k.PublicKey
		if name == "wrong-key" {
			pub = &other.PublicKey
		}
		if _, err := Verify(pub, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReplay(t *testing.T) { // POS-003
	rp := NewReplay()
	r := report()
	if err := rp.Check(&r); err != nil {
		t.Fatal(err)
	}
	if rp.Check(&r) == nil {
		t.Fatal("exact replay accepted")
	}
	older := report()
	older.TS = r.TS.Add(-time.Minute)
	if rp.Check(&older) == nil {
		t.Fatal("older ts accepted")
	}
	same := report()
	same.TS = r.TS
	if rp.Check(&same) == nil {
		t.Fatal("non-increasing ts accepted")
	}
	newer := report()
	newer.TS = r.TS.Add(time.Minute)
	if err := rp.Check(&newer); err != nil {
		t.Fatal(err)
	}
	noNonce := report()
	noNonce.TS, noNonce.Nonce = newer.TS.Add(time.Minute), ""
	if rp.Check(&noNonce) == nil {
		t.Fatal("empty nonce accepted")
	}
	other := report()
	other.DeviceID = "d2"
	other.TS = r.TS.Add(-time.Hour)
	if err := rp.Check(&other); err != nil {
		t.Fatal("replay state must be per device")
	}
}

func TestProbeParsers(t *testing.T) { // POS-004 (inline samples; golden files later)
	tr, fa := true, false
	eq := func(name string, got *bool, want *bool) {
		t.Helper()
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	eq("fdesetup on", ParseFdesetup("FileVault is On.\n"), &tr)
	eq("fdesetup off", ParseFdesetup("FileVault is Off.\n"), &fa)
	eq("fdesetup localised", ParseFdesetup("FileVault ist aktiviert.\n"), nil)
	eq("fdesetup empty", ParseFdesetup(""), nil)
	eq("bde on", ParseManageBde("    Protection Status:    Protection On\n"), &tr)
	eq("bde off", ParseManageBde("    Protection Status:    Protection Off\n"), &fa)
	eq("bde localised", ParseManageBde("Schutzstatus: Schutz aktiviert"), nil)
	eq("ufw active", ParseUFW("Status: active\n"), &tr)
	eq("ufw inactive", ParseUFW("Status: inactive\n"), &fa)
	eq("ufw missing", ParseUFW("ufw: command not found"), nil)
	eq("alf on", ParseSocketFilter("Firewall is enabled. (State = 1)"), &tr)
	eq("alf off", ParseSocketFilter("Firewall is disabled. (State = 0)"), &fa)
	eq("lsblk crypt", ParseLsblkCrypt("disk\npart\ncrypt\nlvm\n"), &tr)
	eq("lsblk none", ParseLsblkCrypt("disk\npart\n"), &fa)
	eq("lsblk empty", ParseLsblkCrypt(""), nil)
}

func FuzzVerify(f *testing.F) {
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, s string) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if _, err := Verify(&k.PublicKey, s); err == nil {
			t.Fatal("random token verified")
		}
	})
}
