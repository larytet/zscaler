package signed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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

func TestSignVerify(t *testing.T) {
	k := key(t)
	now := time.Now()
	e, _ := Sign(k, 10, now, []byte(`{"x":1}`))
	if err := e.Verify(&k.PublicKey, 9, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) { // SEC-007
	k, other := key(t), key(t)
	now := time.Now()
	good, _ := Sign(k, 10, now, []byte(`{"x":1}`))
	cp := func() Envelope {
		c := *good
		c.Payload = append([]byte(nil), good.Payload...)
		c.Sig = append([]byte(nil), good.Sig...)
		return c
	}
	tamper := cp()
	tamper.Payload = []byte(`{"x":2}`)
	reseq := cp()
	reseq.Seq = 11 // a replay attacker cannot raise the sequence number either
	retime := cp()
	retime.Signed = now.Add(time.Hour).Unix()
	short := cp()
	short.Sig = short.Sig[:10]
	empty := cp()
	empty.Payload = nil
	for name, tc := range map[string]struct {
		e    Envelope
		pub  *ecdsa.PublicKey
		last int64
		want error
	}{
		"tampered payload": {tamper, &k.PublicKey, 9, ErrBadSignature},
		"altered sequence": {reseq, &k.PublicKey, 9, ErrBadSignature},
		"altered time":     {retime, &k.PublicKey, 9, ErrBadSignature},
		"wrong key":        {*good, &other.PublicKey, 9, ErrBadSignature},
		"short signature":  {short, &k.PublicKey, 9, ErrBadSignature},
		"empty payload":    {empty, &k.PublicKey, 9, ErrBadSignature},
		"replay same seq":  {*good, &k.PublicKey, 10, ErrReplay},
		"replay older seq": {*good, &k.PublicKey, 50, ErrReplay},
	} {
		if err := tc.e.Verify(tc.pub, tc.last, now, time.Minute); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", name, err, tc.want)
		}
	}
	if err := good.Verify(&k.PublicKey, 9, now.Add(2*time.Minute), time.Minute); !errors.Is(err, ErrTooOld) {
		t.Errorf("stale signature: %v", err)
	}
}
