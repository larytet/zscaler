# Test Plan: SMB-ZTX Reference Build 1 (RB1)

**Status:** Draft v0.2, 2026-11-15
**Inputs:** [REQUIREMENTS.md](REQUIREMENTS.md) v0.4, [DESIGN.md](DESIGN.md) v1.0
**Scope:** only what RB1 builds (DESIGN.md D1.2). Requirements outside RB1 are listed as *not tested* in section T6.

Written in parts, one subtask per commit:

| Part | Content | Status |
|---|---|---|
| T1 | Strategy, levels, environments, policy and unit tests | done |
| T2 | Data plane, agent and end-to-end tests | done |
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

---

## T2. Data plane, agent and end-to-end tests

Design reference: D3, D4, D5.1. Rig: T1.3.

### T2.1 Private access (broker and connector)

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| PA-001 | L4 | P1 | Enrolled user in allowed group, compliant posture, opens segment, sends 1 MB random data to echo app | Data returns identical, decision log has `allow` and rule ID, close record has byte counts | ZPA-020, 022 |
| PA-002 | L4 | P1 | Same user, not in group | `REJECT policy`, echo app saw **zero** connections, log has `deny` | ZPA-020 |
| PA-003 | L4 | P1 | Posture says disk not encrypted | Denied, reason names posture rule in admin log, generic message to user | AGT-006 |
| PA-004 | L4 | P1 | Posture goes from compliant to non-compliant mid-session | Session closed by the next re-evaluation, at most 5 minutes (test uses a shortened interval) | ARCH-006 |
| PA-005 | L4 | P1 | Agent names a segment that does not exist | `REJECT unknown-app`, no connector contact | ZPA-021 |
| PA-006 | L4 | P1 | Agent asks for a raw private IP instead of a segment name | Rejected, never forwarded to a connector | ZPA-010 |
| PA-007 | L3 | P1 | Connector receives `OPEN` for host:port outside its target allow-list (EN sends it directly in a test) | Connector refuses, no dial attempted, event logged | ZPA-023 |
| PA-008 | L4 | P1 | Port scan from outside against the app host's network: connector host has no inbound port opened by the product | No listening port belongs to the connector (checked with `ss`) | ZPA-010 |
| PA-009 | L4 | P1 | Two connectors in a group, kill one during idle | New sessions succeed through the other | ZPA-012 |
| PA-010 | L4 | P1 | Two connectors, kill the one serving a live session | That session closes, a new session works | ZPA-012 |
| PA-011 | L4 | P1 | No connector connected | `REJECT unavailable` within 5 s, logged | ZPA-012 |
| PA-012 | L4 | P2 | Connector reconnect after EN restart | Reconnects with backoff (observed delays within 0 to 30 s), becomes usable | ZPA-011 |
| PA-013 | L4 | P2 | 100 sessions open and closed in a loop 100 times | No stream, goroutine or memory leak (checked by counters and `runtime` stats) | NFR-001 |
| PA-014 | L4 | P2 | Half-close: client sends FIN and waits for reply data | Reply data still delivered | ZPA-022 |
| PA-015 | L4 | P2 | Upstream app refuses connection | Agent sees a clear `unreachable` error, log has `connect-failed` | ZPA-022 |
| PA-016 | L4 | P1 | Segment target changed by admin while connector connected | Connector's allow-list updates within 30 s, old target refused after that | ZPA-023 |
| PA-017 | L4 | P2 | Multi-port segment, port outside the list | Denied | ZPA-020 |

### T2.2 Web proxy

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| WEB-001 | L4 | P1 | HTTP GET to an allowed local test origin | Content returned unmodified, log has `allow` | ZIA-001 |
| WEB-002 | L4 | P1 | `CONNECT` to an allowed HTTPS test origin, TLS handshake and request | Works end to end, proxy did not terminate TLS (certificate seen is the origin's) | ZIA-001 |
| WEB-003 | L4 | P1 | Host in category `malware` | HTTP 403 block page with category and reference ID, origin not contacted | ZIA-010 |
| WEB-004 | L4 | P1 | Host is a subdomain of a blocked domain | Blocked | ZIA-010 |
| WEB-005 | L4 | P1 | Look-alike host (`notblocked.com` vs `blocked.com`) | Not blocked | ZIA-010 |
| WEB-006 | L4 | P1 | `warn` category over plain HTTP | Interstitial page, continue link works once and expires after its lifetime, decision logged as `warn` then `allow` | ZIA-011 |
| WEB-007 | L4 | P1 | `warn` category over HTTPS `CONNECT` | Behaves as allow, log has `warn-not-displayable` (documented limit) | ZIA-011 |
| WEB-008 | L4 | P1 | SSRF: request to `127.0.0.1`, `169.254.169.254`, `10.0.0.1`, `[::1]` | Blocked, logged | NFR-023 |
| WEB-009 | L4 | P1 | SSRF through DNS: test name resolving to a private address, and a name that changes between lookups (rebinding) | Blocked at dial time | NFR-023 |
| WEB-010 | L4 | P1 | Client without a valid device certificate connects to proxy port | Handshake refused, no proxying | ARCH-005 |
| WEB-011 | L4 | P2 | Header over 16 KiB, slow-loris style headers, idle connection for 70 s | Rejected or closed per limits | NFR-023 |
| WEB-012 | L4 | P2 | Log inspection after a request with a query string and a request body | Neither appears in any log or on disk | ARCH-003 |
| WEB-013 | L4 | P2 | Absolute-URI request, `Proxy-Connection`, chunked bodies, `Expect: 100-continue` | Correct behaviour per RFC 9110 and 9112 | ZIA-001 |
| WEB-014 | L4 | P2 | 5 000 sequential requests to local origin | No errors, memory stable | NFR-001 |

### T2.3 Agent, enrolment and identity

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| AG-001 | L4 | P1 | Full login against the test IdP, agent receives 12 h cert | Cert subject is `tenant/user/device`, key file mode 0600 and directory 0700 | INT-001 |
| AG-002 | L4 | P1 | Login with each bad token from IDP-002 | Enrolment fails, no cert issued, failure audited | INT-001 |
| AG-003 | L4 | P1 | OAuth `state` mismatch and missing PKCE verifier on callback | Rejected | INT-001 |
| AG-004 | L4 | P1 | Group list in IdP changes, user logs in again | New groups apply to the next decision | INT-002 |
| AG-005 | L4 | P1 | Admin disables the user | Live sessions close within 5 s, renewal fails, new sessions refused | AGT-004 |
| AG-006 | L4 | P1 | Admin revokes the device | Same as AG-005 for that device, other devices of the user unaffected | AGT-004 |
| AG-007 | L4 | P1 | Cert expiry (shortened to 20 s in test), agent renews before expiry with refresh token | Sessions keep working across renewal, no new login prompt | AGT-004 |
| AG-008 | L4 | P2 | Refresh token invalid | Access ends at cert expiry, agent status says why | AGT-004 |
| AG-009 | L3 | P1 | Local listeners bind to loopback only | Not reachable from a non-loopback address | NFR-020 |
| AG-010 | L4 | P2 | PAC file routes `*.ztx` to SOCKS and others to HTTP proxy | Matches spec for a set of URLs | AGT-002 |
| AG-011 | L4 | P2 | Agent below minimum version announced by the CP | Warns and refuses new sessions | AGT-011 |
| AG-012 | L4 | P2 | EN list with first entry down | Agent uses the next, and returns to the first when it recovers | NFR-002 |
| AG-013 | L4 | P2 | Posture report sent every 5 minutes and on change | Cadence observed, EN holds the latest | AGT-006 |
| AG-014 | L4 | P1 | Connector enrolment: token used twice, token expired, token for another tenant | Only the first valid use succeeds | ZPA-011 |

### T2.4 Control plane and admin API

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| CP-001 | L3 | P1 | Create tenant, set IdP, create segment, apply safe defaults, via API | 2xx, audit entries for each, policy version increments | ADM-001, SMB-001 |
| CP-002 | L3 | P1 | Save an invalid policy (corpus from VAL tests) | 4xx with `code`, nothing stored, no version bump | D2.7 |
| CP-003 | L3 | P1 | Concurrent saves with stale `If-Match` | One succeeds, the other gets 412 | D5.1 |
| CP-004 | L3 | P1 | Tenant A admin token on tenant B objects (every endpoint) | 404 or 403, never data | ARCH-020 |
| CP-005 | L3 | P1 | Viewer role attempts a write | 403 | ADM-003 |
| CP-006 | L3 | P1 | Dry run of a draft policy for a sample request | Returns the decision and the rule, stores nothing | ADM-003 |
| CP-007 | L4 | P1 | Policy change reaches the EN | New decisions use new version within 5 s, decision log shows the version | ARCH-001 |
| CP-008 | L4 | P1 | Stop the CP while sessions are live and new sessions arrive | Sessions continue, new sessions still decided with cached policy | ARCH-002 |
| CP-009 | L4 | P1 | CP down for 16 minutes (fake clock) | New sessions denied because revocation data is stale, then recover after the CP returns | D3.6 |
| CP-010 | L3 | P1 | Policy stream message with a bad CP signature | EN ignores it, keeps the previous version, raises an error metric | D5.5 |
| CP-011 | L3 | P2 | Pagination and filters on `/decisions` and `/audit` | Correct, stable cursor | ADM-006 |
| CP-012 | L3 | P1 | Audit log after a series of admin changes | Complete and hash chain valid | ADM-006 |

### T2.5 Alerts and plain-language summaries

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| ALR-001 | L3 | P2 | 10 denies for the same user and app in 10 minutes | One alert with the message and recommended action in D5.3, not ten | SMB-003 |
| ALR-002 | L3 | P2 | Connector offline for 2 minutes then back | Alert opens and closes | SMB-003 |
| ALR-003 | L3 | P2 | Posture goes from pass to fail | Alert names the failed check | SMB-003 |
| ALR-004 | L3 | P3 | Email delivery to a test SMTP server | Message arrives with the text and a link | OPS-001 |

### T2.6 Full scenarios (L4 acceptance flows)

| ID | Priority | Scenario |
|---|---|---|
| SCN-001 | P1 | **Day one.** Create tenant, connect test IdP, create one segment, apply safe defaults, enrol a connector, enrol one user, reach the echo app, and be blocked from a malware-category host. Measure wall-clock time of the scripted flow, and record it against the SMB-001 goal of under 30 minutes (manual steps timed separately in a usability check) |
| SCN-002 | P1 | **Leaver.** User in active session is disabled by admin. Session ends within 5 s, no new access, audit trail complete |
| SCN-003 | P1 | **Lost laptop.** Device revoked while a transfer is in flight. Transfer stops, the user's second device still works |
| SCN-004 | P1 | **Bad posture.** Disk encryption turned off on a test device, access to a posture-protected segment ends, other segments unaffected, alert raised |
| SCN-005 | P2 | **Site outage.** Both connectors of a site go down and come back, agents show a clear error then resume without re-login |
| SCN-006 | P2 | **Contractor.** Group with access to one segment only, tries a second segment and a web category that is blocked |
