// Package posture signs, verifies and parses device posture reports
// (DESIGN.md D4.3). Reports are compact ES256 JWS tokens.
package posture

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/larytet/zscaler/internal/devhealth"
	"github.com/larytet/zscaler/internal/policy"
)

// Report is the signed payload. Tri-state fields are pointers: nil = unknown.
type Report struct {
	DeviceID      string    `json:"device_id"`
	TS            time.Time `json:"ts"`
	Nonce         string    `json:"nonce"`
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	DiskEncrypted *bool     `json:"disk_encrypted"`
	FirewallOn    *bool     `json:"firewall_on"`
	ScreenLock    *bool     `json:"screen_lock"`
	AgentVersion  string    `json:"agent_version"`
	// Health is optional device health (CPU, memory, disk), signed along with the posture.
	Health *devhealth.Snapshot `json:"health,omitempty"`
}

// ToPolicy converts a verified report for the policy engine.
func (r *Report) ToPolicy() *policy.Posture {
	return &policy.Posture{OS: r.OS, OSVersion: r.OSVersion, DiskEncrypted: r.DiskEncrypted,
		FirewallOn: r.FirewallOn, ScreenLock: r.ScreenLock, ReportedAt: r.TS}
}

var enc = base64.RawURLEncoding

const header = `{"alg":"ES256","typ":"posture+jws"}`

func NewNonce() string {
	b := make([]byte, 12)
	rand.Read(b)
	return enc.EncodeToString(b)
}

func Sign(key *ecdsa.PrivateKey, r Report) (string, error) {
	pl, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	in := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(pl)
	h := sha256.Sum256([]byte(in))
	rr, ss, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return in + "." + enc.EncodeToString(sig), nil
}

var ErrBadReport = errors.New("posture: invalid report")

func Verify(pub *ecdsa.PublicKey, token string) (*Report, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrBadReport
	}
	hdr, err := enc.DecodeString(parts[0])
	if err != nil || string(hdr) != header { // pins the algorithm; rejects "none"
		return nil, ErrBadReport
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, ErrBadReport
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, ErrBadReport
	}
	pl, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadReport
	}
	var r Report
	if err := json.Unmarshal(pl, &r); err != nil {
		return nil, ErrBadReport
	}
	return &r, nil
}

// Replay rejects a nonce seen before and any timestamp not newer than the
// last accepted one for that device.
type Replay struct {
	mu    sync.Mutex
	last  map[string]time.Time
	nonce map[string]map[string]bool
}

func NewReplay() *Replay {
	return &Replay{last: map[string]time.Time{}, nonce: map[string]map[string]bool{}}
}

var ErrReplay = errors.New("posture: replayed report")

func (rp *Replay) Check(r *Report) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if r.Nonce == "" {
		return ErrReplay
	}
	if t, ok := rp.last[r.DeviceID]; ok && !r.TS.After(t) {
		return ErrReplay
	}
	n := rp.nonce[r.DeviceID]
	if n == nil {
		n = map[string]bool{}
		rp.nonce[r.DeviceID] = n
	}
	if n[r.Nonce] {
		return ErrReplay
	}
	if len(n) > 1024 { // bounded: monotonic ts already blocks old nonces
		n = map[string]bool{}
		rp.nonce[r.DeviceID] = n
	}
	n[r.Nonce] = true
	rp.last[r.DeviceID] = r.TS
	return nil
}

// Baseline checks the minimum security baseline used for alerts: disk
// encryption and the host firewall must both be known to be on. Unknown fails.
func Baseline(r *Report) (ok bool, failing []string) {
	check := func(v *bool, name string) {
		switch {
		case v == nil:
			failing = append(failing, name+" could not be checked")
		case !*v:
			failing = append(failing, name+" is off")
		}
	}
	check(r.DiskEncrypted, "disk encryption")
	check(r.FirewallOn, "the firewall")
	return len(failing) == 0, failing
}
