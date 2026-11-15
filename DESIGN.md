# Software Design: SMB-ZTX

**Status:** Draft v0.4, 2026-11-15
**Input:** [REQUIREMENTS.md](REQUIREMENTS.md) v0.4 (IDs such as `ZPA-020` refer to it)
**Next documents:** TEST-PLAN.md, then the implementation under `cmd/` and `internal/`

The design is written in parts. This file grows one subtask at a time:

| Part | Content | Status |
|---|---|---|
| D1 | Scope of the first build, architecture, technology choices | done |
| D2 | Policy engine and data model | done |
| D3 | Data plane: broker, connector stitching, forward proxy | done |
| D4 | Agent, posture, enrolment | done |
| D5 | Control-plane API, logging, security, deployment | pending |

---

## D1. Scope, architecture, technology

### D1.1 Why a reduced first build

REQUIREMENTS.md has 228 requirement IDs aimed at parity with a company of thousands of engineers. One build cannot cover it. This design therefore defines:

- **Target architecture:** how the full product is shaped, so that nothing in the first build blocks the rest.
- **Reference build (RB1):** a small, runnable subset that proves the core zero-trust loop end to end on one machine or a small cluster. This is what the implementation subtasks build and the test plan covers.

RB1 is **not a product**. It does not carry TLS inspection, DLP, sandbox, global PoPs or a production agent. It exists to validate the architecture and the policy model.

### D1.2 RB1 scope (requirement IDs)

| Area | In RB1 | Requirement IDs | Deferred |
|---|---|---|---|
| Architecture | Separate control and data planes, tenant isolation, policy cached at the enforcement point | ARCH-001, 002, 003, 005, 006, 020 | PoP fleet, risk scoring (ARCH-007), per-tenant CA (ARCH-021) |
| Private access | Outbound-only connector, broker stitches inbound and outbound legs, app segments, access policy on user/group/posture, dark apps | ZPA-001..003, 010..012, 020..026 (core subset) | Browser access, PRA, B2B, PSE |
| Web access | Forward proxy (HTTP and CONNECT) with domain and category policy, allow/block/warn, no decryption | ZIA-001..005, 010..014 (subset) | TLS inspection, sandbox, DLP, CASB |
| Agent | CLI agent: enrol, report posture, route private-app and web traffic to the nearest enforcement node via a local proxy | AGT-001, 002, 004 (subset) | Native tunnel driver, per-OS installers |
| Identity | OIDC login, groups from the ID token claims | INT-001, 002 (subset) | SAML, SCIM |
| Posture | Signed posture report: OS version, disk encryption flag, firewall flag | AGT-006 (subset) | EDR integrations |
| Admin | JSON API and a minimal web UI, audit log, safe-defaults policy pack | ADM-001, 003, SMB-001, 002 (subset) | MSP console, Terraform, SIEM streaming |
| Logging | Structured JSON logs of every decision | ADM-006 (subset) | Log streaming, retention tiers |
| Non-functional | Fail-closed, mTLS between internal parties, no payload at rest | NFR-001..003, 020..023 (subset) | Everything involving scale and SLAs |

Every RB1 item above that points to "subset" must list the part it implements in the test plan, so partial coverage is explicit.

### D1.3 Architecture

```
                    +---------------------------+
                    |      Control plane        |
   Admin ---------> |  API + UI + policy store  | <------ IdP (OIDC)
                    |  Tenant, users, apps,     |
                    |  policy, audit, CA        |
                    +------+-------------+------+
                           | policy       | enrolment
                           | push (gRPC-  | tokens, certs
                           | like stream) |
              +------------v--+        +--v----------------+
              | Enforcement   |        |      Agent        |
              | node (EN)     |<-------| (on the endpoint) |
              |  - broker     | TLS    |  - local proxy    |
              |  - web proxy  | 443    |  - posture        |
              |  - decision   |        +-------------------+
              |    cache      |
              +------^--------+
                     | outbound-only TLS (initiated by connector)
              +------+--------+
              |   Connector   |----> private app (TCP)
              | (in customer  |
              |  network)     |
              +---------------+
```

**Components**

| Component | Role | Runs where |
|---|---|---|
| Control plane (CP) | Source of truth for tenants, users, apps, policy. Issues enrolment tokens and short-lived certificates. Never sees user traffic. | One service per region |
| Enforcement node (EN) | Policy enforcement point. Hosts the broker and the web proxy. Holds a cached copy of the tenant policy. | Several per region |
| Connector | Sits next to private apps. Dials out to an EN, waits for session requests, dials the app. No inbound ports. | Customer network |
| Agent | Runs on the endpoint. Authenticates the user, gathers posture, forwards traffic to an EN. | Employee device |

**Flows**

1. **Enrolment.** Admin creates a tenant, connects an IdP, and creates an app segment. A connector is enrolled with a one-time token, receives a client certificate from the CP, and opens a persistent mTLS connection to an EN. A user signs in through the agent (OIDC), the CP verifies the ID token and issues a short-lived device-bound certificate.
2. **Private access.** The agent asks the EN for `app.corp:5432`. The EN looks up the segment, evaluates policy (user, groups, posture, time), and on allow asks the matching connector over its existing connection to open a stream to the app. The EN stitches the two streams. On deny it closes the stream and logs the reason. The app address is never exposed to the client (dark app, ZPA-010).
3. **Web access.** The agent sends HTTP and CONNECT requests to the EN proxy. The EN classifies the host (domain list and category list), evaluates policy, and allows, blocks, or serves a warning page.
4. **Policy change.** The admin edits policy in the CP. The CP validates it, versions it, and pushes the new version to all ENs. ENs apply it atomically. If the CP is unreachable, ENs keep enforcing the last good version (ARCH-002).

### D1.4 Design principles for RB1

1. **Deny by default.** A request with no matching allow rule is denied (ZIA-016 equivalent for web is configurable, private access is always default-deny).
2. **Control plane never carries traffic.** An outage of the CP must not drop established sessions or stop enforcement with cached policy.
3. **Connectors never accept inbound connections.** All connector links are outbound-initiated.
4. **Every decision is explainable.** Each log record carries the rule ID that matched, or `default-deny`.
5. **Fail closed on posture.** A missing, expired or badly signed posture report counts as non-compliant.
6. **No traffic payload at rest.** ENs hold streams in memory only (ARCH-003).
7. **Small and boring.** One language, few dependencies, one binary per role, so a small team can run and audit it.

### D1.5 Technology choices

| Choice | Decision | Reason | Alternative rejected |
|---|---|---|---|
| Language | Go | Good TLS, concurrency and static binaries. Fits connector and agent footprint. Toolchain already installed (1.27). | Rust: better memory safety, slower to iterate for RB1 |
| Dependencies | Standard library first (`crypto/tls`, `net/http`, `encoding/json`, `log/slog`). Add third-party only for OIDC verification if the stdlib route is too costly. | Fewer supply-chain risks, easier audit | Large frameworks |
| Internal transport | mTLS over TCP with a length-prefixed stream multiplexer (own small framing in RB1, `yamux`-style) | Connector needs many streams over one outbound connection | gRPC: heavier, defer |
| Control-plane storage | Interface with a JSON-file store for RB1, SQLite-compatible schema for later | No external service to run for tests | Postgres: right for production, overkill for RB1 |
| Policy format | JSON rules, evaluated in priority order, first match wins | Matches Zscaler-style ordered rules (section 6.2) and is simple to test | Rego/Cedar: powerful, new dependency and learning cost |
| Identity | OIDC authorization code with PKCE | Works for the common SMB IdPs (Entra ID, Google, Okta) | SAML first |
| Posture | JSON report signed with the device key | Verifiable without a vendor service | Third-party EDR APIs |

### D1.6 Repository layout (target)

```
cmd/
  ztx-cp/         control plane
  ztx-en/         enforcement node
  ztx-connector/  connector
  ztx-agent/      agent CLI
internal/
  policy/         rule model and evaluator
  store/          store interface + JSON-file implementation
  pki/            CA, certificate issuance
  mux/            stream multiplexer over one connection
  broker/         session brokering and stitching
  webproxy/       forward proxy and classification
  posture/        posture report model, signing, verification
  audit/          decision log
  idp/            OIDC verification
test/
  e2e/            end-to-end tests that start all four binaries
```

### D1.7 Known risks carried into later parts

- **Patents.** Connector stitching and handshake snooping are covered by patent families named in REQUIREMENTS.md section 15. RB1 uses a connector-initiated outbound link, which is a general technique, but claim scope was not read. A freedom-to-operate opinion is needed before any commercial use. RB1 is for evaluation.
- **Inspection versus end-to-end encryption.** RB1 does not decrypt, which sidesteps ZPA-031 versus ZPA-041. It also means web policy works on host names only.
- **Posture trust.** A self-signed posture report from an unmanaged device is only as honest as the device. RB1 treats it as a signal for the SMB case, and the threat model in D5 states this.

---

## D2. Policy engine and data model

Requirements: ARCH-005, ARCH-006, ZPA-020..026 (subset), ZIA-010..014 (subset), SMB-002.

### D2.1 Entities

All entities carry `id` (string, unique within a tenant), `tenant_id`, `created_at`, `updated_at`, `version`.

| Entity | Fields | Notes |
|---|---|---|
| Tenant | `name`, `idp` (issuer, client_id, group_claim), `ca` reference | Isolation boundary (ARCH-020) |
| User | `subject` (OIDC `sub`), `email`, `groups[]`, `disabled` | Created at first login. Groups refreshed at each login |
| Device | `user_id`, `public_key`, `posture` (last report), `enrolled_at`, `revoked` | Key generated on the device |
| Connector | `name`, `cert_serial`, `site`, `last_seen`, `revoked` | Enrolled with a one-time token |
| AppSegment | `name`, `connector_group`, `targets[]` (`host`, `ports[]`, `proto`) | Targets are never sent to the agent |
| Rule | see D2.2 | Ordered in a policy |
| Policy | `kind` (`private` or `web`), `rules[]`, `default_action`, `version` | One of each kind per tenant in RB1 |
| CategoryList | `category` to `domains[]` | Static lists in RB1, feed later |
| AuditEvent | `ts`, `actor`, `action`, `object`, `before`, `after` | Append-only |
| DecisionLog | see D2.5 | Written by ENs |

### D2.2 Rule model

```json
{
  "id": "r-finance-db",
  "priority": 10,
  "action": "allow",
  "match": {
    "users":    ["alice@example.com"],
    "groups":   ["finance"],
    "apps":     ["seg-erp-db"],
    "posture":  {"min_os": {"windows": "10.0.19045", "macos": "13.0"},
                 "disk_encrypted": true, "firewall_on": true,
                 "max_age_seconds": 3600},
    "time":     {"days": ["mon","tue","wed","thu","fri"], "from": "07:00", "to": "20:00", "tz": "Europe/Berlin"},
    "network":  {"src_cidrs": ["0.0.0.0/0"]}
  },
  "reason": "Finance staff reach the ERP database"
}
```

Web rules replace `apps` with `domains[]` (suffix match), `categories[]`, and may use `action: "warn"`.

**Semantics**

1. Within one condition type, entries are OR. Across condition types, AND. An absent condition matches everything.
2. Users and groups together: the rule matches if the user is in `users` **or** in any `groups` (OR within the "who" dimension). If both are absent, anyone authenticated matches.
3. Rules are sorted by `priority` ascending. The first matching rule wins. If none match, `default_action` applies. For `private`, `default_action` must be `deny` and the validator rejects anything else.
4. Actions: `allow`, `deny`, and for web `warn` (interstitial, user may continue, logged).
5. `posture` conditions are all required. A missing or stale report fails the condition, so an `allow` rule does not match and evaluation continues (fail closed, principle 5).
6. A disabled user, revoked device, or revoked connector short-circuits to `deny` before rule evaluation.

### D2.3 Evaluator interface

```go
package policy

type Request struct {
    Kind     Kind       // Private or Web
    User     User
    Device   Device     // includes verified posture, and when it was verified
    App      string     // segment ID, for private
    Host     string     // lowercase host, for web
    Port     int
    SrcIP    netip.Addr
    Now      time.Time
}

type Decision struct {
    Action  Action // Allow, Deny, Warn
    RuleID  string // "" means default
    Reason  string
}

func (p *Policy) Evaluate(r Request) Decision
func Validate(p *Policy) []error
```

Properties required of `Evaluate`:

- **Pure:** no I/O, no clock reads (time comes from `Request.Now`), deterministic. This makes table-driven and property tests simple.
- **Fast:** under 50 microseconds for 500 rules (rules are pre-indexed by `apps` and by domain suffix in a compiled form). Compilation happens once per policy version.
- **Total:** always returns a decision. Internal errors turn into `Deny` with reason `evaluation-error`.

### D2.4 Safe-defaults pack (SMB-002)

Shipped as data, applied by the setup wizard:

| Priority | Kind | Rule |
|---|---|---|
| 10 | web | deny categories `malware`, `phishing`, `command-and-control` |
| 20 | web | warn categories `newly-registered`, `file-sharing-unsanctioned` |
| 1000 | web | allow everything else (web default is `allow` in RB1) |
| 10 | private | allow group `all-staff` to each app segment marked `standard`, posture required |
| 20 | private | allow group `admins` to segments marked `admin`, posture required |
| default | private | deny |

### D2.5 Decision log record

```json
{"ts":"2026-11-15T10:00:00Z","tenant":"t1","kind":"private","user":"alice@example.com",
 "device":"d-17","app":"seg-erp-db","target":"10.0.0.5:5432","action":"allow",
 "rule":"r-finance-db","policy_version":42,"en":"en-eu-1","latency_ms":3,"bytes_up":0,"bytes_down":0}
```

Closing a session emits a second record with byte counts. Logs never contain request bodies or full URLs with query strings (host and port only in RB1), which keeps the "no payload" principle.

### D2.6 Policy distribution

- The CP stores policies versioned by a monotonically increasing integer per tenant.
- ENs keep a long-lived stream to the CP. On connect, the EN sends the last version it holds and receives anything newer. A push carries the full compiled-policy input (not a diff) in RB1, since tenant policies are small (under 1 MB).
- The EN swaps the compiled policy atomically (`atomic.Pointer`). In-flight sessions keep the version they started under, but long sessions are re-evaluated every 5 minutes or on a revocation event, so a revoked device loses access within 5 minutes at most (NFR target to be stated in the test plan).
- Revocations (user disabled, device revoked, connector revoked) are pushed immediately as a separate event and close live sessions.

### D2.7 Validation rules

`Validate` rejects: duplicate rule IDs or priorities, an unknown action, a `private` default other than deny, an `allow` rule with no `users`, no `groups` and no `posture` and no `apps` (an accidental allow-all), unparsable CIDRs or time zones, references to unknown segments, and domain entries that contain schemes or paths. Warnings (not errors): a rule that can never match because an earlier rule shadows it.

---

## D3. Data plane: broker, connector, web proxy

Requirements: ZPA-001..003, 010..012, 020..026 (subset), ZIA-001..005 (subset), ARCH-002, ARCH-003.

### D3.1 Stream multiplexer (`internal/mux`)

A connector keeps one outbound TLS connection to an EN and must carry many concurrent app sessions over it. RB1 uses a small framing protocol over the TLS stream.

Frame: `type(1) | stream_id(4) | length(4) | payload`.

| Type | Meaning |
|---|---|
| `OPEN` | Initiator opens a stream. Payload: JSON `{"app":"seg-id","host":"…","port":5432}` for connector streams |
| `ACCEPT` / `REJECT` | Answer to `OPEN`. `REJECT` carries a short reason code |
| `DATA` | Stream bytes |
| `FIN` | Half-close |
| `RST` | Abort |
| `WINDOW` | Flow-control credit (per stream, 256 KiB initial) |
| `PING` / `PONG` | Liveness every 15 s, connection dropped after 45 s of silence |

Stream IDs: odd for streams opened by the EN, even for the connector (unused in RB1). A mux error on one stream never tears down the connection. Flow control prevents one slow app from filling memory.

Alternative considered: use an existing multiplexer library. Acceptable replacement later, because the package exposes only `Session.Open`, `Session.Accept`, and `Stream` (an `io.ReadWriteCloser`).

### D3.2 Enforcement node internals (`cmd/ztx-en`)

```
 listeners                    decision                    upstream
 :443  agent TLS (mTLS) --->  authenticate (cert)  --->   connector mux session   (private)
 :8443 connector TLS    --->  register connector          direct dial to origin    (web)
 :3128 proxy (agent)    --->  classify + evaluate  --->
```

Roles in one process, selectable by flag, so a small deployment runs a single EN.

**Registries (in memory)**

- `connectors`: map of connector ID to live mux session and its `connector_group`. Multiple connectors in a group give load sharing and failover (ZPA-012).
- `sessions`: active stitched sessions, with user, device, app, policy version, start time. Used for revocation and for re-evaluation.
- `policy`: the current compiled policy per tenant, from D2.6.

### D3.3 Private-access session flow

1. Agent opens mTLS to `:443`. The EN verifies the device certificate chain, checks revocation in its cached list, and reads tenant, user and device from the certificate subject. A certificate older than its validity (12 hours default) is rejected.
2. Agent sends `OPEN {app: "seg-erp-db", port: 5432}`. The agent only names a segment (or a hostname the agent resolves to a segment through its local config), never a raw private IP. The segment definition is on the EN.
3. EN builds a `policy.Request` using the **latest verified posture** held for that device (posture arrives at connect and every 5 minutes, see D4).
4. `Deny`: the EN sends `REJECT` with code `policy`. It logs `deny` with the rule ID. The user-facing reason is generic. Admins see the rule.
5. `Allow`: the EN picks a live connector in the segment's group (round-robin among healthy), sends `OPEN {host, port}` over the connector mux, waits up to 5 s for `ACCEPT`.
6. On `ACCEPT`, the EN replies `ACCEPT` to the agent and copies bytes both ways (`io.Copy` with the mux flow control). On `REJECT` or timeout it tries the next connector once, then fails with `unavailable`.
7. Either side closing produces `FIN` then closure. The EN writes the second log record with byte counts.

**Target allow-list.** The connector independently refuses any `host:port` not in its configured segment targets (received from the CP at enrolment and kept updated). This means a compromised EN cannot make a connector dial arbitrary internal hosts. Defence in depth, ZPA-023.

**Dark apps.** The app has no listener reachable from outside. The connector dials out only. The EN never returns the target address to the agent (ZPA-010).

### D3.4 Connector (`cmd/ztx-connector`)

- Starts with `--token` the first time. Generates a keypair, exchanges the token for a certificate with the CP, stores the key and cert with mode 0600.
- Dials the EN list from the CP (primary, then others) with exponential backoff and jitter up to 30 s.
- Serves `OPEN` requests: checks the target allow-list, dials the target with a 3 s timeout, relays bytes.
- Holds no user data and no policy beyond the target allow-list. Runs fine as an unprivileged user in a container.
- Health: reports `last_seen`, active streams and version over the control stream every 10 s.

### D3.5 Web proxy (`internal/webproxy`)

- Supports HTTP forward proxying and `CONNECT` for HTTPS. **No TLS interception in RB1.**
- Authentication: the agent connects over mTLS to the proxy port (so identity is the device certificate) and RB1 does not support unauthenticated clients.
- Classification: take the host from the `Host` header or `CONNECT` target, lowercase, strip the port. Look up the host in the category list by walking domain suffixes (`a.b.example.com`, `b.example.com`, `example.com`) against a map. Result: zero or more categories.
- Evaluate `policy.Request{Kind: Web, Host, Categories}`.
  - `Allow`: dial the origin (with a deny for private and loopback ranges, to stop SSRF into the EN's own network), stitch.
  - `Deny`: HTTP 403 (or `CONNECT` 403) with a short block page naming the category, a support contact, and a reference ID that ties to the log.
  - `Warn`: for plain HTTP, an interstitial page with a continue link carrying a signed, short-lived token. For `CONNECT` (no decryption) a warning page cannot be shown inside TLS, so RB1 treats `warn` on HTTPS as `allow` and logs `warn-not-displayable`. That limit is explicit in the test plan.
- DNS: the EN resolves origins itself with a resolver that rejects answers in private ranges. DNS-level filtering for non-proxied traffic is deferred.
- Limits: header size 16 KiB, idle timeout 60 s, max 10 000 concurrent connections per EN (configurable).

### D3.6 Failure behaviour

| Failure | Behaviour |
|---|---|
| CP unreachable | ENs keep enforcing the last policy. No new enrolments. Revocation pushes stall, so the EN re-checks the cached revocation list age and denies new sessions if it is older than 15 minutes (configurable) |
| Connector disconnects | Its streams close. New sessions go to other connectors in the group, or fail with `unavailable` |
| EN crashes | Agents reconnect to the next EN in their list. Connectors reconnect to another EN |
| Policy fails to compile | Rejected by the CP at save time. An EN that still receives a bad version keeps the previous one and reports an error |
| Clock skew | Certificates validated with 2 minutes of tolerance. Posture reports older than their `max_age` are treated as missing |

### D3.7 Performance and resource targets for RB1

Stated so the test plan can check them. They are design targets, not parity with Zscaler.

- Added latency for a private TCP session setup on one machine: under 20 ms at the 95th percentile.
- Throughput through one EN for a single stream on loopback: at least 500 Mbit/s.
- 1 000 concurrent stitched sessions on one EN with under 300 MB of memory.
- Connector idle memory under 30 MB.

---

## D4. Agent, posture, enrolment

Requirements: AGT-001, 002, 004, 006 (subsets), INT-001, 002 (subset), SMB-001.

### D4.1 Agent (`cmd/ztx-agent`)

RB1 agent is a cross-platform CLI/daemon. It is not a kernel-level tunnel. It exposes local listeners and routes traffic to an EN:

| Local listener | Purpose |
|---|---|
| `127.0.0.1:1080` SOCKS5 | Private-app access. Each configured app gets a virtual hostname (for example `erp-db.ztx`) and the agent maps a SOCKS request for that name to the segment ID |
| `127.0.0.1:3129` HTTP proxy | Web traffic. The agent forwards to the EN proxy over mTLS |
| `127.0.0.1:9100` status | JSON health and last posture, local only, for support |

Browsers and tools are pointed at the local proxy by a PAC file the agent serves (`/proxy.pac`) that sends `*.ztx` names to SOCKS and everything else to the HTTP proxy. A transparent tunnel driver (TUN/WFP/Network Extension) is a later part and out of RB1 scope (AGT-002 gap, stated in the test plan).

Agent state lives in a per-user config directory (mode 0700): `device.key` (private key, never leaves the device), `device.crt`, `config.json` (CP URL, EN list). Key storage in the OS keystore or TPM is deferred.

### D4.2 Enrolment and login

```
agent                      CP                          IdP
  | --- generate keypair ---|                           |
  | --- GET /auth/start ---->                           |
  |<-- redirect URL + PKCE --|                           |
  | ---------------- browser login ---------------------> 
  |<--------------- code to local callback --------------|
  | --- POST /auth/finish (code, verifier, CSR) -------->|
  |                         | exchange code, verify ID token
  |                         | upsert user, groups
  |<-- device cert (12 h) --|
```

Steps and rules:

1. The agent starts a loopback HTTP listener on a random port for the OAuth redirect and opens the system browser. Authorisation code flow with PKCE (S256) and a random `state`.
2. The CP exchanges the code and **verifies the ID token**: signature against the issuer's JWKS (cached, refreshed on unknown `kid`), `iss`, `aud`, `exp` with 2 minutes of tolerance, `nonce`. The `groups` come from the configured claim.
3. The CP rejects unknown tenants, disabled users, and tokens where `email_verified` is false (when the claim exists).
4. The agent sends a certificate signing request. The CP signs a **12-hour** client certificate with subject `tenant/user/device` and an extended key usage of client authentication. The private key stays on the device.
5. Renewal: the agent renews 1 hour before expiry using a refresh token (stored with mode 0600). If the IdP session is gone or the user was disabled, renewal fails and access ends at certificate expiry, or earlier by revocation push.
6. First-run for SMB-001: an admin enters the tenant name and IdP details in the wizard. Staff receive an install link and a one-time device-enrolment page.

Connector enrolment uses a one-time token from the admin UI (valid 1 hour, single use, bound to the tenant and the connector group). The CP stores only a hash of the token.

### D4.3 Posture

The agent builds a report every 5 minutes and on change:

```json
{"device_id":"d-17","ts":"2026-11-15T10:00:00Z","nonce":"…",
 "os":"windows","os_version":"10.0.19045",
 "disk_encrypted":true,"firewall_on":true,"screen_lock":true,
 "agent_version":"0.1.0"}
```

- Signed with the device key (ECDSA P-256, detached JWS). The EN verifies the signature with the public key from the device record.
- Collection per OS: Windows (`manage-bde -status`, `netsh advfirewall show allprofiles`), macOS (`fdesetup status`, `socketfilterfw --getglobalstate`), Linux (`lsblk` with crypto type detection, `ufw status` or `nft list ruleset`). Each probe has a timeout and a result of `true`, `false` or `unknown`, and `unknown` is treated as `false` by policy (fail closed).
- Sent on the agent's existing mTLS connection to the EN (`POSTURE` control stream, the same connection as sessions).
- The EN keeps the latest valid report per device for as long as the device is connected. Reports are replay-protected by `ts` and `nonce` (monotonic `ts` within a connection).

**Threat model note.** A compromised device can lie in a self-reported posture. This is the same trust level as most lightweight agents. The signed report ties the claim to an enrolled device key and prevents spoofing by someone else, but not by malware on that device. The EDR integrations in AGT-006 raise this and are deferred.

### D4.4 Revocation

- The admin can revoke a device or disable a user. The CP records it, increments a revocation sequence, and pushes it to every EN.
- ENs close the affected live sessions within 5 seconds and reject the certificate afterwards. Certificates are short-lived (12 hours), so a missed push is bounded.
- ENs keep a revocation list of (serial, expiry), pruned after expiry. If they have not heard from the CP for more than 15 minutes, new sessions are denied (see D3.6).

### D4.5 Updates

RB1 provides a version check: the CP announces a minimum agent version and the agent warns and, below the minimum, refuses to start sessions. Automatic update is deferred (AGT-011 gap).

### D4.6 Privacy

Posture contains only the fields above. No process list, no browsing history, no file names. The decision log stores user, device, app or host and action. This is consistent with REQUIREMENTS.md section 12.4 and should stay narrow unless a customer opts in.
