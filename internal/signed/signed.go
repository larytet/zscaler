package signed

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Envelope is a signed state snapshot (DESIGN.md D5.5, SEC-007). The signature
// covers the sequence number, the signing time and the payload bytes, so a
// captured snapshot cannot be replayed once a newer one has been accepted.
type Envelope struct {
	Seq     int64  `json:"seq"`     // strictly increasing
	Signed  int64  `json:"signed"`  // unix seconds
	Payload []byte `json:"payload"` // JSON snapshot
	Sig     []byte `json:"sig"`     // r || s, 32 bytes each
}

func digest(seq, signed int64, payload []byte) [32]byte {
	var h [16]byte
	binary.BigEndian.PutUint64(h[:8], uint64(seq))
	binary.BigEndian.PutUint64(h[8:], uint64(signed))
	return sha256.Sum256(append(append([]byte("smb-ztx state v1\x00"), h[:]...), payload...))
}

func Sign(key *ecdsa.PrivateKey, seq int64, now time.Time, payload []byte) (*Envelope, error) {
	d := digest(seq, now.Unix(), payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return &Envelope{Seq: seq, Signed: now.Unix(), Payload: payload, Sig: sig}, nil
}

var (
	ErrBadSignature = errors.New("sync: state signature invalid")
	ErrReplay       = errors.New("sync: state is not newer than the last accepted one")
	ErrTooOld       = errors.New("sync: signed state is too old")
)

// Verify checks the signature, then freshness and monotonicity. lastSeq is the
// highest sequence already accepted. maxAge bounds how old the signature may be.
func (e *Envelope) Verify(pub *ecdsa.PublicKey, lastSeq int64, now time.Time, maxAge time.Duration) error {
	if len(e.Sig) != 64 || len(e.Payload) == 0 {
		return ErrBadSignature
	}
	d := digest(e.Seq, e.Signed, e.Payload)
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(e.Sig[:32]), new(big.Int).SetBytes(e.Sig[32:])) {
		return ErrBadSignature
	}
	if e.Seq <= lastSeq {
		return fmt.Errorf("%w (seq %d, have %d)", ErrReplay, e.Seq, lastSeq)
	}
	if now.Sub(time.Unix(e.Signed, 0)) > maxAge {
		return ErrTooOld
	}
	return nil
}
