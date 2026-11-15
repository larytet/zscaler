# Software Design: SMB-ZTX

**Status:** Draft v0.1, 2026-11-15
**Input:** [REQUIREMENTS.md](REQUIREMENTS.md) v0.4 (IDs such as `ZPA-020` refer to it)
**Next documents:** TEST-PLAN.md, then the implementation under `cmd/` and `internal/`

The design is written in parts. This file grows one subtask at a time:

| Part | Content | Status |
|---|---|---|
| D1 | Scope of the first build, architecture, technology choices | this commit |
| D2 | Policy engine and data model | pending |
| D3 | Data plane: broker, connector stitching, forward proxy | pending |
| D4 | Agent, posture, enrolment | pending |
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
