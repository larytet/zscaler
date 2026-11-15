# Test Plan: SMB-ZTX Reference Build 1 (RB1)

**Status:** Draft v1.0 (complete for RB1), 2026-11-15
**Inputs:** [REQUIREMENTS.md](REQUIREMENTS.md) v0.4, [DESIGN.md](DESIGN.md) v1.0
**Scope:** only what RB1 builds (DESIGN.md D1.2). Requirements outside RB1 are listed as *not tested* in section T6.

Written in parts, one subtask per commit:

| Part | Content | Status |
|---|---|---|
| T1 | Strategy, levels, environments, policy and unit tests | done |
| T2 | Data plane, agent and end-to-end tests | done |
| T3 | Security, resilience, performance tests, traceability, exit criteria | done |
| T4, T5 | Workspace browser; agentic-AI security | done (see below) |
| T7 | Real-environment tests on a Linux node with Kubernetes, driven by the requirements | plan written, suite in progress |

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

---

## T3. Security, resilience, performance, traceability, exit criteria

### T3.1 Security tests

Design reference: D5.5 threat table.

| ID | Level | Priority | Threat | Case | Expected |
|---|---|---|---|---|---|
| SEC-001 | L4 | P1 | Stolen device cert | Use a cert on a different machine without the key (handshake with the cert only) | Handshake fails |
| SEC-002 | L4 | P1 | Stolen cert, still valid | Revoke, then connect | Refused, live sessions closed within 5 s |
| SEC-003 | L4 | P1 | Cross-tenant | Device of tenant A requests a segment ID belonging to tenant B | Treated as unknown segment, no side effect |
| SEC-004 | L4 | P1 | Rogue EN | Connector connects to a fake EN with a certificate from a different CA | Connector refuses to connect |
| SEC-005 | L4 | P1 | Rogue connector | Client with an agent cert (not a connector cert) tries to register as a connector | Refused |
| SEC-006 | L3 | P1 | Compromised EN | EN sends `OPEN` to an arbitrary internal host | Covered by PA-007, connector refuses |
| SEC-007 | L4 | P1 | Policy tampering | Replay an old policy version, and a version signed by a different key | EN rejects both (version must increase, signature must verify) |
| SEC-008 | L4 | P1 | Admin API auth | No token, wrong token, token of a deleted admin, token in URL | 401 in all cases, nothing logged in clear |
| SEC-009 | L3 | P1 | Secrets in logs | Run the e2e suite with a log scanner for tokens, keys, refresh tokens, JWTs and cookies | Zero matches |
| SEC-010 | L3 | P1 | Token storage | Inspect store files for enrolment and admin tokens | Only hashes present |
| SEC-011 | L4 | P1 | TLS config | Scan each listener for protocol versions and ciphers | TLS 1.2 minimum (1.3 preferred), no weak ciphers, no renegotiation, correct SNI behaviour |
| SEC-012 | L4 | P2 | DoS: connection flood | 5 000 new connections per second from one device identity | Per-device limit applies, other devices unaffected |
| SEC-013 | L4 | P2 | DoS: stream flood | One connector session opens streams until the cap | Cap enforced, session survives, others unaffected |
| SEC-014 | L4 | P2 | Log sink full | Fill the decision-log disk | EN refuses new sessions beyond the threshold, alerts, recovers when space returns |
| SEC-015 | L3 | P1 | Path and injection | Fuzz API path and JSON fields with traversal strings, long strings, control characters | No crash, no file access outside the data directory |
| SEC-016 | L3 | P1 | OAuth redirect | Callback listener bound to loopback only, rejects callbacks from other origins, one use only | Pass |
| SEC-017 | L6 | P1 | Static analysis | `go vet`, `staticcheck`, `govulncheck` | No findings of severity high, no known vulnerable dependencies |
| SEC-018 | L6 | P1 | Race detector | Full L1 to L4 with `-race` | Clean |
| SEC-019 | L6 | P2 | Fuzz budget | 30 minutes per fuzz target (mux, policy loader, proxy request parser, JWT parser) nightly | No crash found, corpus saved |
| SEC-020 | L4 | P2 | Hash-chained audit | Tamper with a stored audit record | Verification command reports the break |

### T3.2 Resilience and failure injection

| ID | Priority | Fault | Expected |
|---|---|---|---|
| RES-001 | P1 | Kill and restart the EN during 50 live sessions | Sessions drop, agents and connectors reconnect within 30 s, no stuck state |
| RES-002 | P1 | Network delay of 200 ms and 2% loss between agent and EN | Sessions work, throughput degrades gracefully, no timeouts below 10 s |
| RES-003 | P1 | Connection reset in the middle of a mux frame | The one session fails cleanly, no goroutine leak |
| RES-004 | P2 | Disk full on the connector host | Connector keeps relaying (it writes nothing important), logs a warning |
| RES-005 | P2 | Clock jump of plus and minus 10 minutes on the agent | Clear error (cert not yet valid or posture rejected), no crash, recovers after correction |
| RES-006 | P2 | Corrupt `config.json` and `device.crt` on the agent | Agent starts, reports the problem, offers re-enrolment |
| RES-007 | P1 | 24 hour soak with 200 sessions churning | Memory growth under 10%, no goroutine growth, no errors above baseline |

### T3.3 Performance tests (design targets from D3.7)

Run on a documented machine class (record CPU, RAM, kernel). Each is a target, not parity with Zscaler. A miss is recorded and reviewed, not hidden.

| ID | Metric | Target | Method |
|---|---|---|---|
| PERF-001 | Private session setup latency (agent to echo app, loopback) | p95 under 20 ms | 10 000 sequential setups |
| PERF-002 | Single-stream throughput through EN and connector on loopback | at least 500 Mbit/s | `iperf`-style transfer of 5 GB |
| PERF-003 | 1 000 concurrent stitched sessions | EN memory under 300 MB, no errors | Load tool holding sessions open for 10 minutes |
| PERF-004 | Connector idle memory | under 30 MB | Measure after 10 minutes idle |
| PERF-005 | Policy evaluation | under 50 microseconds with 500 rules | Go benchmark (POL-028) |
| PERF-006 | Policy push to 20 ENs | all applied within 5 s | Simulated ENs |
| PERF-007 | Web proxy throughput | at least 1 000 requests per second for small objects on one core | Load tool |
| PERF-008 | Decision-log write overhead | under 5% added latency at 1 000 decisions per second | A/B run with and without the sink |

### T3.4 Usability checks (manual, SMB goals)

| ID | Check | Pass criterion |
|---|---|---|
| USE-001 | A person with IT basics but no security background follows the wizard on a clean machine | First protected user in under 30 minutes (SMB-001). Record time and every point of confusion |
| USE-002 | Admin reads five generated alerts | Each makes sense without documentation and offers a single action (SMB-003) |
| USE-003 | A blocked end user sees the block page | Can tell what happened and who to contact |

### T3.5 Traceability (RB1 scope)

Requirements marked "subset" in DESIGN.md D1.2 are covered only for the behaviour the tests exercise. The gap column states what is not covered.

| Requirement | Tests | Gap in RB1 |
|---|---|---|
| ARCH-001, 002, 003 | CP-007, CP-008, CP-009, WEB-012, PERF-006 | No multi-region, no active-active across regions |
| ARCH-005, 006 | POL-009..012, PA-004, WEB-010, AG-005..007 | No risk score (ARCH-007) |
| ARCH-020 | STO-001, CP-004, SEC-003 | One CA with tenant in subject (ARCH-021 not met) |
| ZPA-010..012 | PA-006, PA-008..012, AG-014 | Single region, no PSE |
| ZPA-020..026 | PA-001..005, PA-007, PA-016, PA-017, POL-xxx | No browser access, no PRA, no B2B |
| ZIA-001..005, 010..014 | WEB-001..009, WEB-013, POL-021..025 | No TLS inspection, no URL path rules, no sandbox, no DLP, `warn` on HTTPS not displayable |
| AGT-001, 002, 004 | AG-001, AG-005..010 | No tunnel driver, no installers, no auto-update (AGT-011 partial) |
| AGT-006 | POS-001..004, PA-003, AG-013 | Self-reported posture only, no EDR |
| INT-001, 002 | IDP-001..004, AG-001..004 | No SAML, no SCIM |
| ADM-001, 003, 006 | CP-001..006, CP-011, CP-012 | No MSP console, no SIEM streaming, no Terraform |
| SMB-001, 002, 003 | SCN-001, USE-001, USE-002, VAL-012, ALR-001..003 | Cyber-insurance export, exposure scan not built |
| NFR-001..003 | PA-013, WEB-014, RES-001..007, PERF-001..008 | No SLA or capacity claims |
| NFR-020..023 | AG-009, SEC-001..016, WEB-008, WEB-009 | No external penetration test |

### T3.6 Not tested in RB1 (explicit)

TLS inspection, DLP, CASB, sandbox, browser isolation, GenAI controls, digital experience monitoring, branch and cloud connectors, firewall (L3/L4 and DNS/IPS) beyond host rules, bandwidth control, B2B, privileged remote access, MSP multi-tenancy, data residency, compliance certification. These need their own plan when they enter scope.

### T3.7 Defect handling and exit criteria

Severity: **S1** security bypass, data exposure or wrong allow. **S2** wrong deny of legitimate traffic, crash, leak. **S3** incorrect message, cosmetic.

RB1 exit requires:

1. All P1 tests pass on three consecutive nightly runs.
2. No open S1 or S2 defect.
3. P2 failures each have an owner, a decision (fix or accept) and a note.
4. Design-target misses in T3.3 are listed in the release notes.
5. Traceability table has no requirement in RB1 scope without tests.
6. `govulncheck` clean on the release commit, third-party dependency list reviewed.
7. USE-001 done by at least two people who did not write the product.

### T3.8 Test automation layout

```
internal/<pkg>/*_test.go     L1, L2, benchmarks
test/testdata/               policy corpora, golden posture outputs, category lists
test/idp/                    in-process OIDC test provider
test/faults/                 fault-injecting TCP proxy
test/e2e/                    L4 scenarios (build tag e2e)
test/load/                   L5 load tool
Makefile targets             test, test-race, test-e2e, fuzz, bench, vuln
```

CI stages: build, vet and staticcheck, L1 to L3 with race, L4 fast subset, then nightly: full L4, fuzz, soak, performance, vulnerability scan.

---

## T4. Workspace browser (requirements v0.6, DESIGN D8)

> **Version 1 of the workspace browser is a proof of concept (requirements v0.7, option C), and it has no data controls.** The tests below that need the in-browser extension, installers or a per-launch proxy credential are marked **Deferred to v2**. A deferred test is **not failing and not skipped by accident**: the thing it tests does not exist in v1, and the product must not claim it. They come back into scope if option A (bundled Chromium) or B (enterprise policy) is built (DESIGN D8.7). The exit condition at the end of this section is for the proof of concept only.

Written with the design, before any implementation. IDs continue the plan's scheme. "Stub browser" means a small program standing in for Chromium that records its command line, environment and working files and exits on request; it lets the launcher be tested without a real browser. Items marked **manual** need a person and a real browser.

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| WBT-001 | L1 | P1 | Policy condition `workspace` true and false, with and without the action `isolate`, in web and private rules | Matches only the intended side; `isolate` outside the workspace is `deny` with reason `workspace-required` | WB-008 |
| WBT-002 | L1 | P1 | Validation: `isolate` in a rule with no domains, categories or apps; unknown values | Rejected | WB-008 |
| WBT-003 | L1 | P1 | Certificate role `workspace`: issued only to an enrolled workspace; verified; cannot be used where a connector or EN certificate is required, and a plain `device` certificate cannot claim it | Role is read from the certificate only | WB-004 |
| WBT-004 | L3 | P1 | EN sets `Workspace` from the role for broker sessions and web requests; a `device` certificate sets it false whatever the client sends | Decision and log show `workspace` correctly | WB-004, WB-009 |
| WBT-005 | L4 | P1 | A `sensitive` segment from a plain agent | Denied with a message saying how to get the workspace | WB-008 |
| WBT-006 | L4 | P1 | The same segment from the workspace | Allowed; record shows `workspace: true` | WB-008 |
| WBT-007 | L3 | P1 | Launcher with the stub browser: profile directory, proxy flag, QUIC and ECH switched off, no extension or debugging flags, no sync, environment contains no personal profile path | All present; none of the forbidden flags | WB-002, WB-003, WB-005 |
| WBT-008 | L3 | P1 | Launcher refuses a request to start with extra browser flags (`--remote-debugging-port`, `--load-extension`, `--user-data-dir` elsewhere) | Refuses and says why | WB-005 |
| WBT-009 | L3 | P1 | **Deferred to v2 (credential part).** **Changed in W1:** the per-launch proxy credential cannot be delivered by flags (DESIGN D8.2) and moves to W3 with the extension. W1 instead checks that the local proxies listen on loopback ephemeral ports only and stop when the workspace ends. The credential test (requests without it, stale, from another process) stays open for W3 | Loopback only; ports closed after exit. Credential test: not yet | WB-003 |
| WBT-010 | L3 | P1 | Sign-out, revoke, admin erase and idle timeout | Browser process ends and the profile directory is gone | WB-002 |
| WBT-011 | L3 | P1 | Posture loop with a fake clock: pass, fail, unknown, stale | Fail, unknown and stale lock the workspace within one cycle; recovery needs a fresh pass | WB-007 |
| WBT-012 | L3 | P2 | Control plane unreachable longer than the grace period | Workspace locks; before the grace period it keeps working | WB-011 |
| WBT-013 | L4 | P1 | Revoke the device while a workspace session is open | Session ends within seconds; the profile is erased | WB-004 |
| WBT-014 | L4 | P2 | Secret scan over launcher output and logs | No tokens, credentials or certificate keys | WB-009 |
| WBT-015 | **manual** | P1 | **Deferred to v2 (installers; v1 only times the command-line launcher, see the runbook).** Install on a clean Windows, macOS and Linux machine by someone who did not build it, from an invitation link | Under 5 minutes, no administrator rights where the OS allows; timed and written down | WB-001 |
| WBT-016 | **manual** | P1 | With a real Chromium: personal bookmarks, passwords, sync and extensions are absent; a personal browser window on the same device is unaffected | Confirmed by observation | WB-002 |
| WBT-017 | **manual** (automated in part by SCN-015) | P1 | With a real Chromium: inspected HTTPS works inside the workspace and the personal browser still shows the original certificates | SCN-015 shows both with real headless Chrome on Linux. Still to do by hand: a visible window (any notice about the flag), the device's system trust store compared before and after, macOS and Windows | WB-003 |
| WBT-018 | **manual** | P1 | **Deferred to v2: there are no data controls in v1.** Clipboard, download, upload, print and drag-and-drop controls, per policy | Each blocked or allowed as configured; blocked events logged without content. In v1 the only check is that nothing claims these controls exist | WB-006 |
| WBT-019 | **manual** | P2 | Screenshot and screen-share behaviour on each OS | Documented per OS; the console states what is active | WB-006, WB-013 |
| WBT-020 | **manual** | P1 | The launcher's start-up notice, the first-run screen and the admin console state the limits | v1: the launcher notice says proof of concept and lists the missing controls (automated by SCN-011); the first-run screen and console text are still to be written and checked by a person | WB-013 |

**Deferred tests (not failing):** WBT-009 (credential part), WBT-015, WBT-018. WBT-019 (screenshots) is not deferred: it records that v1 does **not** block them. Entry for implementation slice W1: WBT-001 to WBT-014 written as failing tests first. Exit for the proof of concept (RB-WB v1): all P1 automated tests that are not deferred pass on three consecutive runs, and WBT-016, WBT-017, WBT-019 and WBT-020 have been done by at least two people who did not build the workspace. WBT-009 (credential), WBT-015 and WBT-018 are deferred and are not part of this exit. Until then the workspace browser is described everywhere as "not yet verified on real browsers".

---

## T5. Agentic-AI security (requirements v0.8, DESIGN D9)

Written before the slices it covers. Priorities follow the requirements: Should items are P2 unless marked. "Agent" means an identity `agent:<name>` (I12b).

| ID | Level | Priority | Case | Expected | Req |
|---|---|---|---|---|---|
| AGT-001 | L3 | P1 | A rule with `inject` on an allowed request to the secret's host | The origin receives the header with the secret; the agent's own header of that name is replaced | AGS-001 |
| AGT-002 | L3 | P1 | The secret is bound to host A, the request goes to host B | Denied, nothing injected, the secret never sent to B | AGS-001 |
| AGT-003 | L3 | P1 | The request is denied by policy | The secret is not injected and the origin is not contacted | AGS-001 |
| AGT-004 | L4 | P1 | Secret scan over the agent's responses, the decision log, captures, block pages, the secrets list API and the audit log | The secret value appears nowhere | AGS-001 |
| AGT-005 | L3 | P1 | Rule with `inject` on traffic that is not inspected | Denied with a reason that says inspection is needed | AGS-001 |
| AGT-006 | L3 | P1 | Secrets API: create, list, replace, delete; viewer role; another tenant | List shows names and hosts only; writes need admin; tenants isolated; audited without the value | AGS-001 |
| AGT-007 | L3 | P2 | Read-only pack: GET and HEAD allowed on listed domains, POST, PUT, PATCH and DELETE denied (web rules cannot use approval), other domains denied, model provider allowed, warnings when inspection is off | Each case decided as stated, for agents only | AGS-002, AGS-003 |
| AGT-008 | L3 | P2 | The same pack for a person | No effect on people | AGS-002 |
| AGT-009 | L3 | P1 | Operator cap: the operator is disabled, restricted, or loses access to the app | The agent is denied at once | AGS-004 |
| AGT-010 | L3 | P1 | An agent granted an app its operator may not reach | Denied, reason says the operator lacks access | AGS-004 |
| AGT-011 | L3 | P2 | Shadow-AI report over a set of decisions | Counts per person and AI tool; people with no AI use absent; tenant isolated | AGS-016 |
| AGT-012 | L3 | P2 | Rule-of-two lint: an agent that can read private apps, reach untrusted input and write out | Warning naming the three; an agent missing one leg gets none | AGS-017 |
| AGT-013 | L4 | P2 | End to end with real binaries: an agent with an injected credential reaches a TLS origin, the origin sees the credential, the agent process never held it | As stated | AGS-001 |
| AGT-014 | L3 | P2 | Per-agent volume cap | Pause and alert at the limit; owner can resume | AGS-009 |
| AGT-015 | manual | P2 | An owner who is not a security expert reads the agent registry, the approval request and the rule-of-two warning | Understands each without help (add to USABILITY-RUNBOOK) | Principle 5 |
| AGT-016 | L3 | P2 | Agent registry: created, last use, access end, unused after 30 days | Shown; a used agent is not flagged; tenant isolated | AGS-005 |
| AGT-017 | L2/L3/L4 | P1 | Exact data match (DATA-006): a listed value in a decrypted request or response; a value one character off; other case; a long token containing it | Listed values blocked (also in other case and before a full stop), others pass; only hashes stored; sets listed as counts; a rule naming an unknown set refused; delete of a set in use refused; SCN-020 with real binaries | DATA-006 (exact data match part) |
| AGT-018 | L2/L3 | P2 | Path stages (DEX-002): parse the router and Wi-Fi tables; probe each stage with a fake network; score a slow connection with each stage bad in turn | Each stage measured or left unknown (a timeout is never zero); nothing contacted that was not asked for; the cause names wifi, local-network, dns, isp or cloud as the first bad stage from the device outwards; a fast connection is never made to look slow | DEX-002 (basic) |
| AGT-019 | L2/L3 | P2 | Removable media posture (DATA-005, basic): parse `lsblk`; the agent reports it on Linux only; a rule with `removable_media: false` | Mounted removable drive refused, none allowed, unknown fails closed; not guessed on other systems | DATA-005 (posture part) |
| AGT-020 | L2/L3/L4 | P1 | Index document match (DATA-006, documents): verbatim copy, copy inside other text, other case and punctuation, a ten-word excerpt, a short phrase, unrelated text, a copy with a word changed in every run, speed on 1 MB; only hashed runs stored; SCN-020 pasted copy blocked | Copies and excerpts of about ten words or more blocked; short phrases, edited copies and unrelated text pass; the text is never stored or returned | DATA-006 (document part) |
| AGT-021 | L2/L3 | P1 | Policy history (ADM-004): save three versions; list; diff; read one; roll back with a stale, missing and right If-Match; unknown version; another tenant; audit; the 50-version cap; restart; a policy saved before history | Versions listed with who saved them; diff names added, removed and changed rules and the default; rollback saves the old content as a new version and never rewrites history; refused without If-Match, for a version not kept, and across tenants | ADM-004 |

Not covered in this plan until built: AGS-007 chat approval, AGS-008, AGS-010, AGS-011, AGS-012, AGS-014, AGS-015 (decision log chain), AGS-018.


---

## T7. Real-environment tests (a Linux node with Kubernetes)

### T7.1 Why

T1 to T5 run on one machine with everything on loopback, in-process fakes for the identity provider and the
browser, and binaries started by the test. They prove the logic. They do not prove that the product works
when its parts run where they would really run: a connector in a container inside a cluster, private apps as
cluster services, real container networking, real process restarts and a real clock. T7 adds that, and every
test in it is named after the requirements it checks, so the suite can be read against REQUIREMENTS.md.

### T7.2 What the owner provides

The tests need one Linux x86-64 **test node**, supplied by the person running them. The plan assumes only this:

| Need | Detail |
|---|---|
| Access | `ssh <username>@<servername>` works with a key (no password prompt) |
| Privilege | `sudo` works without a password on the node |
| Tools on the node | `rsync`, `docker`, `kubectl` (cluster access, possibly through `sudo`), `curl`, `python3`. Go is **not** installed on the node: the code is built inside a Docker container (image `golang:<version named in go.mod>`, pulled once) |
| Cluster | A running Kubernetes cluster that `kubectl` on the node can reach (a single-node kind cluster is enough) |
| Size | At least 4 CPUs and 8 GB of memory free; a few GB of disk |
| Network | The node can reach its own cluster. Outbound internet is needed once, to pull the build image (unless it is already there), and by the tests that say they need it (those are skipped, with the reason printed, when it is missing) |

The node is given to the suite through environment variables, never written into the repository:

| Variable | Meaning |
|---|---|
| `ZTX_TEST_NODE` | `<username>@<servername>` |
| `ZTX_TEST_KUBECTL` | the kubectl command on the node, default `sudo kubectl` |
| `ZTX_TEST_DOCKER` | the docker command on the node, default `sudo docker` |
| `ZTX_TEST_REGISTRY` | a registry the cluster can pull from, if one exists (default: load images into the cluster directly) |
| `ZTX_BUILD_IMAGE` | the Go build image, default `golang:<version in go.mod>` |

### T7.3 Layout

- **Service side, as processes on the node:** the control plane, two enforcement nodes (for redundancy tests) and a
  local test identity provider.
- **Customer side, in the cluster:** the connector as a pod (the deployment the product is designed for), private
  apps as pods and services (a TCP echo app, an HTTP app, a slow app), and an HTTPS origin with a certificate the
  platform does not trust until told to.
- **Endpoints:** agents as processes on the node with separate state directories, standing in for laptops.
- **Driver:** a compiled Go test binary run on the node. It drives the admin API, the agent's local proxies and
  `kubectl`, and checks results from the outside (what the origin received, what the logs and API show).

### T7.4 Safety and clean-up rules (they apply to a shared cluster)

1. Everything the suite creates lives in **one namespace named `ztx-real-<run id>`**, and the run id is random. No
   other namespace, node or cluster-wide object is read for changes or written (no CRDs, cluster roles or
   cluster-scoped objects).
2. The suite refuses to start if that namespace already exists, and deletes it at the end, also when a test fails
   or the run is interrupted. A `clean` command removes leftovers of earlier runs by their label
   (`app.kubernetes.io/part-of=ztx-real-test`) and nothing else.
3. Container images are tagged `ztx-real-<run id>` and removed at the end.
4. Processes on the node run under the test user in a per-run directory and are stopped at the end.
5. Pods have small resource requests and limits. Ports on the node are chosen at random.
6. Keys, tokens and certificates are generated for the run and never stored in the repository.
7. The only change outside the run's namespace and the run's own directory is **one packet-filter rule**, scoped to the cluster node's address and this run's enforcement node port (REAL-PA-007), added and removed by the test, also when it fails. Volumes that connector pods use are claimed in the namespace and removed with it.
8. A failure is a failure: a test is skipped only for a prerequisite named in this plan, with the reason printed.

### T7.5 How a run works

`test/real/run.sh` does: `rsync` the source to a directory on the node; build the product's binaries and one compiled
test binary inside a Docker container (static, CGO off, run as the node user so no file is owned by root, Go cache kept
between runs); run the test binary on the node; copy the log back; record the result. The
results of a run are written to `RESULTS-REAL.md` with the date, the commit, the node's OS and core count (not its
name), and the counts of passed, failed and skipped tests.

### T7.6 Suite, by requirement

Test IDs start with `REAL-`. Each row names the requirements it covers. Rows marked *planned* are written one
family at a time (STATUS.md says which exist).

| ID | Requirements | What is done | Expected |
|---|---|---|---|
| REAL-ENV-001 | T7.2, T7.4 | Check access, privilege, tools and cluster; create and delete the test namespace | Each prerequisite reported; namespace gone afterwards |
| REAL-PA-001 | ZPA-001, ZPA-002, PA-001 | A user reaches an app in the cluster through the connector pod | Data round-trips; the app was reached only by the connector |
| REAL-PA-002 | ZPA-003, PA-007 | The app's service has no external exposure; the connector pod has no listening port | Nothing on the node or cluster answers except through the platform |
| REAL-PA-003 | ZPA-010, ZPA-011, PA-009, PA-010 | Two connector pods; one is deleted | Access continues through the other; the deleted one is replaced and reconnects |
| REAL-PA-004 | ZPA-044, ARCH-003 | Two enforcement nodes; one is killed mid-session | New sessions use the other; established sessions on it end and the agent recovers |
| REAL-PA-005 | PA-002, ZPA-020 | A user outside the allowed group tries the app | Denied; the app was not contacted |
| REAL-PA-006 | PA-016, ZPA-021 | The segment's target is moved to another service | The new target works within the refresh time; the old one does not |
| REAL-PA-007 | NFR-011, NFR-012 | A packet-filter rule on the node cuts the cluster off from the enforcement node's port, then is removed (a NetworkPolicy is not used: it does not drop traffic on connections that already exist) | Access stops (fail closed) and the app is not contacted; it returns by itself, without a restart of the connector pod |
| REAL-AG-001 | AG-005, AG-006, ARCH-006 | Admin disables a user and revokes a device while sessions are open | Sessions close within seconds; other devices of the user are unaffected |
| REAL-AG-002 | AG-007 | Short certificate lifetime on a real clock | The agent renews without a new login |
| REAL-CP-001 | CP-007, ADM-004 | Policy change, then roll back | Takes effect within the sync time; the rollback restores the earlier behaviour |
| REAL-CP-002 | CP-008, NFR-011 | Control plane stopped and started | Established and new sessions continue on cached state; changes resume on return |
| REAL-ZIA-001 | ZIA-001, ZIA-012 | Web requests through the agent's proxy to a service in the cluster | Allowed and blocked by category and domain rules; block page names the reason |
| REAL-ZIA-002 | ZIA-030, ZIA-040, ZIA-032 | TLS inspection of an HTTPS origin in the cluster | Certificate from the tenant CA; exempt domains untouched; path and method rules apply |
| REAL-ZIA-003 | DATA-001, DATA-006 | Uploads with card numbers, listed values and indexed text | Blocked at the node; the origin never receives them |
| REAL-ZIA-004 | ZIA-022b, AGS-001 | Capture and credential injection against an API in the cluster | Capture redacted and admin-only; the key reaches the origin and never the agent or logs |
| REAL-AI-001 | AI-001, AGS-002, AGS-004 | An AI agent identity with the read-only pack and an operator | Reads allowed, writes denied, other destinations denied, no more than the operator may reach |
| REAL-OPS-001 | ADM-005, FW-010, ADM-007 | Decision logs for all of the above | Every session has a record with user, device, rule and reason; no payload content |
| REAL-PERF-001 | NFR-002, NFR-003 | Private-app set-up time and throughput through the connector pod | Reported against the design targets; misses are listed, not hidden |
| REAL-SEC-001 | SEC-001..006, NFR-020 | Stolen certificate without key, foreign CA, old TLS, connector given a target outside its list | Refused in each case; no payload written to disk on the node |

**All 20 tests of the table are written, and all 20 passed together in one run on a one-node kind cluster** (see
RESULTS-REAL.md). The web tests reach an HTTPS origin in the cluster through a node port on the cluster node's address
(the private app of the PA tests is never exposed that way); the enforcement node is started with the lab-only switches
that let it dial that private address and trust the origin's certificate. A requirement is verified in a real
environment only to the extent its test checks it: the results of REAL-PERF-001 are measurements on one machine, not a
capacity claim.

### T7.7 Pass criteria

A run passes when every test that is not skipped for a stated prerequisite passes, `RESULTS-REAL.md` is updated,
and the namespace and images are gone. The suite is run by the owner on a node they provide; the product's own
developers do not claim a requirement as verified in a real environment until its REAL- test has passed there.
