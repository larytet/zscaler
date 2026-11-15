# Test Plan: SMB-ZTX Reference Build 1 (RB1)

**Status:** Draft v0.1, 2026-11-15
**Inputs:** [REQUIREMENTS.md](REQUIREMENTS.md) v0.4, [DESIGN.md](DESIGN.md) v1.0
**Scope:** only what RB1 builds (DESIGN.md D1.2). Requirements outside RB1 are listed as *not tested* in section T6.

Written in parts, one subtask per commit:

| Part | Content | Status |
|---|---|---|
| T1 | Strategy, levels, environments, policy and unit tests | this commit |
| T2 | Data plane, agent and end-to-end tests | pending |
| T3 | Security, resilience, performance tests, traceability, exit criteria | pending |

---

## T1. Strategy, environments, unit and policy tests

### T1.1 Objectives

1. Show that the policy model decides correctly, including fail-closed behaviour.
2. Show that the data plane enforces those decisions and that private apps stay dark.
3. Show that failure modes in DESIGN.md D3.6 behave as designed.
4. Check the design targets in D3.7 and make misses visible.
5. Make every RB1 requirement traceable to at least one test, or to an explicit gap.

### T1.2 Levels

| Level | What | Tooling | Runs |
|---|---|---|---|
| L1 Unit | One package, no network | `go test`, table-driven, `-race` | every commit |
| L2 Property and fuzz | Evaluator and parsers with generated input | `testing/quick`, `go test -fuzz` | commit (short), nightly (long) |
| L3 Component | One binary with fakes for neighbours (for example EN with a fake connector) | `go test` with in-process listeners | every commit |
| L4 End to end | All four binaries, real TLS, local test IdP and local TCP echo "private app" | `test/e2e`, Go test starting processes | every commit (fast subset), nightly (full) |
| L5 Non-functional | Load, soak, failure injection | Go benchmarks, a load tool in `test/load` | nightly and before release |
| L6 Security | Static analysis, dependency audit, targeted attack tests | `go vet`, `staticcheck`, `govulncheck`, test cases in T3 | every commit and nightly |

### T1.3 Environments and fixtures

- **Local e2e rig:** processes on loopback with random ports, temporary directories, short certificate lifetimes for expiry tests (seconds, using an injectable clock where possible).
- **Test IdP:** a minimal in-process OIDC provider that signs ID tokens with a test key, supports PKCE, JWKS rotation, and can emit bad tokens (wrong `aud`, expired, bad signature, missing `nonce`).
- **Private app stub:** TCP echo server, plus a variant that counts connections and records the source address.
- **Fault injection:** a TCP proxy between components that can delay, drop, reset and cut connections.
- **Clock:** the policy evaluator takes time in the request, and the mux, PKI and posture packages take an injectable clock.
- **Data sets:** category lists with known good, bad, and tricky domains (see T1.5), a policy corpus of valid and invalid policies stored under `test/testdata/`.

### T1.4 Entry and exit criteria (summary, full list in T3)

- Entry for L4: L1 to L3 green, race detector clean.
- RB1 exit: all P1 tests pass, no open severity 1 or 2 defect, design-target misses (D3.7) recorded, every requirement in the RB1 scope mapped.

Priority: **P1** must pass for RB1. **P2** should pass. **P3** nice to have.

### T1.5 Policy engine tests (package `internal/policy`)

Design reference: D2.2, D2.3, D2.7. Requirements: ARCH-005, ARCH-006, ZPA-020..026, ZIA-010..014, SMB-002.

| ID | Priority | Case | Expected |
|---|---|---|---|
| POL-001 | P1 | No rules, private request | `Deny`, rule `""`, reason default |
| POL-002 | P1 | One allow rule, user in `groups` | `Allow` with that rule ID |
| POL-003 | P1 | Same rule, user not in group and not in `users` | `Deny` default |
| POL-004 | P1 | User listed in `users` but not in `groups` of the same rule | `Allow` (OR inside the who dimension) |
| POL-005 | P1 | Rule with no `users` and no `groups`, authenticated user | matches |
| POL-006 | P1 | Two rules both match, priorities 10 and 20, actions differ | priority 10 wins |
| POL-007 | P1 | Rules given in unsorted order | result identical to sorted order |
| POL-008 | P1 | `deny` at priority 10, `allow` at 20, both match | `Deny` |
| POL-009 | P1 | Allow rule needs `disk_encrypted`, report says `false` | rule skipped, falls to next rule or default deny |
| POL-010 | P1 | Posture `disk_encrypted` is `unknown` | treated as `false` |
| POL-011 | P1 | No posture report at all, rule requires posture | rule skipped (fail closed) |
| POL-012 | P1 | Posture older than `max_age_seconds` | rule skipped |
| POL-013 | P1 | `min_os` exactly equal, one below, one above (Windows build numbers and macOS) | equal and above match, below skipped |
| POL-014 | P2 | `min_os` with a different OS than the device | rule skipped |
| POL-015 | P1 | Disabled user matches an allow rule | `Deny`, reason `user-disabled` before rules |
| POL-016 | P1 | Revoked device | `Deny`, reason `device-revoked` |
| POL-017 | P1 | Time window: inside, one minute before, one minute after, at boundary | boundary rule documented and tested (start inclusive, end exclusive) |
| POL-018 | P2 | Time window across a DST change in `Europe/Berlin` | local time used, no off-by-hour |
| POL-019 | P2 | Time window `from` later than `to` (overnight) | validator accepts and evaluator handles wrap, or validator rejects, whichever the spec says, tested either way |
| POL-020 | P1 | `network.src_cidrs` match and miss, IPv4 and IPv6 | correct |
| POL-021 | P1 | Web rule with domain `example.com` against `example.com`, `a.example.com`, `notexample.com`, `example.com.evil.net` | first two match, last two do not |
| POL-022 | P1 | Web rule on category, host has two categories, one matches | matches |
| POL-023 | P1 | Web `warn` action returned | `Warn` carried through |
| POL-024 | P2 | Host with uppercase letters, trailing dot, port | normalised before matching |
| POL-025 | P2 | Internationalised domain names (punycode and unicode forms) | same decision for both forms |
| POL-026 | P1 | Evaluate called with an internal error condition (corrupt compiled index injected) | `Deny`, reason `evaluation-error`, no panic |
| POL-027 | P1 | Purity: same request evaluated 1000 times, in parallel with `-race` | same decision, no race |
| POL-028 | P2 | Compile once, evaluate with 500 rules | under 50 microseconds per call (benchmark, D2.3) |

### T1.6 Policy validation tests

| ID | Priority | Case | Expected |
|---|---|---|---|
| VAL-001 | P1 | Duplicate rule ID | error |
| VAL-002 | P1 | Duplicate priority | error |
| VAL-003 | P1 | Unknown action | error |
| VAL-004 | P1 | `private` policy with `default_action: allow` | error |
| VAL-005 | P1 | Allow rule with no users, groups, posture or apps (accidental allow-all) | error |
| VAL-006 | P1 | Bad CIDR, bad time zone, bad time format | error naming the field |
| VAL-007 | P1 | Rule references an unknown segment ID | error |
| VAL-008 | P1 | Domain entry with scheme (`https://x.com`) or path | error |
| VAL-009 | P2 | Rule shadowed by an earlier rule | warning, not an error |
| VAL-010 | P1 | Valid policy corpus (20 files) | no errors |
| VAL-011 | P2 | Invalid policy corpus (30 files, one defect each) | each yields its expected error and nothing else |
| VAL-012 | P2 | Safe-defaults pack | validates, and produces the decisions in D2.4 table for a set of sample requests |

### T1.7 Property and fuzz tests

| ID | Priority | Property |
|---|---|---|
| FUZ-001 | P1 | Evaluator never panics for arbitrary requests and arbitrary valid policies |
| FUZ-002 | P1 | Adding a `deny` rule at priority lower than any other, for a matching request, always yields `Deny` |
| FUZ-003 | P1 | Removing posture from a request never changes a `Deny` into an `Allow` (monotonic fail-closed) |
| FUZ-004 | P1 | Policy JSON loader never panics on arbitrary bytes and rejects anything the validator would reject |
| FUZ-005 | P2 | Domain suffix matcher agrees with a simple reference implementation on random hostnames |

### T1.8 Other unit tests (non-network packages)

| ID | Package | Priority | Case |
|---|---|---|---|
| PKI-001 | `pki` | P1 | Issued device cert has expected subject, 12 h validity, client-auth usage only |
| PKI-002 | `pki` | P1 | Cert signed by another tenant's CA is rejected |
| PKI-003 | `pki` | P1 | Expired cert rejected, and one within the 2-minute tolerance accepted |
| PKI-004 | `pki` | P1 | Revoked serial rejected, pruned after expiry |
| PKI-005 | `pki` | P1 | One-time enrolment token: works once, rejected on second use, rejected after 1 hour, stored hashed |
| POS-001 | `posture` | P1 | Signed report verifies with the device key |
| POS-002 | `posture` | P1 | Altered field, wrong key, and malformed JWS are rejected |
| POS-003 | `posture` | P1 | Replay with the same nonce and with an older `ts` is rejected |
| POS-004 | `posture` | P2 | Probe parsers on captured outputs of `manage-bde`, `fdesetup`, `lsblk`, `ufw` (golden files, including odd or localised output giving `unknown`) |
| IDP-001 | `idp` | P1 | Valid token accepted, groups read from the configured claim |
| IDP-002 | `idp` | P1 | Wrong `iss`, wrong `aud`, expired, bad signature, `alg: none`, missing `nonce`: each rejected |
| IDP-003 | `idp` | P1 | Unknown `kid` triggers one JWKS refresh, then succeeds or fails cleanly (no refresh storm) |
| IDP-004 | `idp` | P2 | `email_verified: false` rejected |
| AUD-001 | `audit` | P1 | Hash chain verifies, and altering or deleting a record is detected |
| STO-001 | `store` | P1 | Every call is scoped by tenant: tenant A cannot read or write tenant B (table of operations) |
| STO-002 | `store` | P2 | Optimistic concurrency: stale `version` is rejected |
| MUX-001 | `mux` | P1 | Round trip of every frame type |
| MUX-002 | `mux` | P1 | 1 000 streams in parallel, data integrity checked by checksum |
| MUX-003 | `mux` | P1 | Flow control: a stalled reader on one stream does not block others, and memory stays bounded |
| MUX-004 | `mux` | P1 | `RST` on one stream leaves the others working |
| MUX-005 | `mux` | P1 | No `PONG` for 45 s closes the session (fake clock) |
| MUX-006 | `mux` | P1 | Frame parser fuzz: oversize length, truncated frame, unknown type, stream ID reuse, never panics or allocates beyond the cap |
