# Status

**Last updated:** 2026-11-15, after the extension-loading test (W3 blocked on a decision).
**Rule:** this file is updated, committed and pushed at the end of every subtask.

## Goal

1. Review the PDFs and write low-hanging ideas for Zscaler into a dedicated md file in `.doc/`.
2. Build a small-business zero-trust product, in this order: requirements spec, software design, test plan, implementation. Work in subtasks, one at a time. Commit and push after each subtask. Keep this status file current.

Implementation language: **Go** (chosen by the user).

## Progress

| # | Subtask | State | Where |
|---|---|---|---|
| 1 | Ideas for Zscaler | done | `.doc/ZSCALER-IDEAS.md` |
| 2a | Requirements spec | done, v0.5 (34 items promoted to Must on request) | `REQUIREMENTS.md` |
| 2b | Software design D1 to D5 | done, v1.0 for RB1 | `DESIGN.md` |
| 2c | Test plan T1 to T3 | done, v1.0 for RB1 | `TEST-PLAN.md` |
| 2d | Deferred-features roadmap | done | `ROADMAP.md` |
| 2e | Implementation | **in progress** | see below |

### Implementation subtasks (RB1)

| ID | Subtask | State | Tests |
|---|---|---|---|
| I1 | Policy engine, validation | done | POL, VAL, FUZ |
| I2a | Stream multiplexer | done | MUX |
| I2b | PKI, posture, audit | done | PKI, POS, AUD |
| I3 | Enforcement node broker, connector, agent client | done | PA, SEC, AG (component level) |
| I4 | Web proxy, classifier, SSRF guard, warn page | done | WEB |
| I5a | Store and control-plane admin API | done | STO, CP, VAL-012 |
| I5b-1 | OIDC ID-token verifier and in-process test IdP | done | IDP |
| I5b-2 | Device and connector enrolment endpoints (cert issuance) | done | AG-001, 002, 004, 005, 006, 014 (server side) |
| I5c | Agent: OIDC login with PKCE, enrolment, renewal, SOCKS and HTTP proxies, PAC, posture probes | done | AG-001, 003, 007..010, RES-006, SEC-016 |
| I5d-1 | Support packages for the binaries: CA persistence, IP SANs, EN enrolment, polled state sync, stale and admin-revoked handling | done | CP-009, 010 (EN side), PKI |
| I5d-2 | `cmd/` binaries for cp, en, connector, agent, plus Makefile | done (build and unit-tested pieces; not yet run together) | PKI persistence |
| I6a | End-to-end test starting the real binaries | done: SCN-001, SCN-002, SCN-004 pass (`make e2e`). SCN-003, 005, 006 not written | SCN |
| I6b | Alerts: repeated denies, connector offline, posture failed; EN event emission, record forwarding, `/v1/alerts` | done: ALR-001..003; SCN-004 also checks the alert end to end. ALR-004 (email) not built | ALR |
| I6c | README run instructions, performance tests (PERF-001..004), fuzz and vulnerability scan, toolchain pin | done. PERF-002 and PERF-005 missed (see RESULTS.md) | PERF, SEC-017..019 |
| I7a | Fix PERF-005 (rule index) and PERF-002 (mux buffer reuse) | done: both targets now met | PERF-002, 005 |
| I7b | PERF-006..008 measurements; EN sync default 5 s to 2 s; cache per-request cert-chain check in the proxy | done: all met | PERF-006..008 |
| I7c | Fault-injecting proxy, RES-001..003, shortened soak RES-007 | done. RES-002 packet loss and RES-004 not tested; RES-007 ran 3 minutes, not 24 h | RES |
| I7d | SCN-003 lost laptop, SCN-005 site outage, SCN-006 contractor, RES-001 with real processes (`make e2e`, 8 tests, about 35 s) | done | SCN |
| I7e | Email alerts: SMTP notifier, per-tenant recipients (`PUT /v1/alert-settings`), `--smtp-*` flags on ztx-cp | done: ALR-004 against an in-process SMTP server; not tried against a real mail provider | ALR |
| I7f | Traceability check, 26 missing or unlabelled tests added, and four missing features built: minimum agent version, per-identity connection limit, refuse sessions when the log cannot be written, cursor pagination; SEC-009 no-secrets scan; policy rollback refusal | done | see RESULTS.md |
| I8a | `/v1/decisions` search with filters and cursor paging; bounded in-memory history per tenant (DESIGN D5.1) | done. History is lost on control-plane restart (the EN file is the durable copy) | CP-011 |
| I8b | Weekly digest (ADM-009): `GET /v1/digest` (JSON or `?format=text`), emailed Mondays 08:00 UTC to the alert recipients when SMTP is configured | done. The scheduler loop itself is not tested (the content, the endpoint and the send are); email only against a fake SMTP server | digest tests |
| I8d | Policy simulation (ZPA-028, ADM-020): decision records now carry the user's groups and the device posture in force; `POST /v1/policies/private/simulate` replays recent decisions against a draft and reports who would be newly allowed or denied | done for private access only. Web decisions cannot be replayed (no category list in records) and source IP is not recorded. Records now hold group names and posture values, a little more than DESIGN D4.6 intended | simulate tests |
| I9a | Signed control-plane state (DESIGN D5.5, SEC-007): the CP signs every snapshot (ECDSA, sequence number and time covered); ENs pin the public key at enrolment and refuse unsigned, forged, tampered, replayed or stale state | done. Closes the SEC-007 gap. ENs enrolled before this must be enrolled again to get the key. The signing key is a file on the control plane (no KMS) | signed, en tests |
| I9b | Admin console (DESIGN D5.2): static page on the admin listener with Overview, Access, People, Apps, Policy (simulate only), Reports, Investigate; token kept in sessionStorage; strict CSP; no HTML-parsing code (a test enforces it) | done; first checked only by tests (serving, headers, the no-HTML-sinks rule, JavaScript syntax), then by hand in a real browser in I11. Beyond reading, it can disable a user, revoke a device, restrict a user, approve or deny requests and change inspection. It cannot edit policies | ui tests |
| I9c | Product-side `restricted` group (ZPA-072): `POST /v1/users/{id}/restrict` and `/unrestrict`; survives IdP group refreshes; the safe-default policies deny it first; console buttons. Live sessions end within seconds (SCN-007) | done. It only helps if the policy has a rule for the group: tenants that wrote their own policy must add one | store, cp tests, SCN-007 |
| I9d | Explainable risk score (ARCH-007): 0 to 100 from four signals (device below baseline, many blocked attempts, repeated web blocks), refreshed every 30 s, carried to ENs in the signed snapshot, usable in rules as `max_risk` / `min_risk`; `GET /v1/risk` shows scores with reasons; console column | done, in simple form. It is a handful of rules, not a model: no behavioural baselines, no external threat feeds. The safe defaults do NOT use it, so nothing is blocked on risk unless an admin writes a rule. Scores are lost on restart until the next refresh. Simulation cannot replay risk rules | risk, policy, cp tests |
| S1 | Spec change on instruction: **use a workspace browser** for unmanaged devices and browser isolation. Requirements v0.6: new family WB-001..WB-013 (section 18.4); ZPA-055, ZIA-022d, ZIA-024 reworded to use it; cloud-streamed isolation moved to ZIA-024b (class C); parity matrix and SMB-007 updated | done (requirements only) | |
| S2 | Design for the workspace browser (DESIGN D8: a launcher plus an extension around a Chromium-family browser, workspace as a certificate role, `workspace` rule condition and `isolate` action, phases W1 to W4) and test plan T4 (WBT-001..020, five need people); also fixed the duplicate D6 numbering in DESIGN.md | done. Open risks recorded: Chrome's limits on loading extensions from the command line, no portable trust-store isolation, no screenshot blocking with a stock browser | |
| S3 | Slice W1 (workspace browser, launcher level): `workspace` certificate role (short-lived, 4 h), `workspace` rule condition, `isolate` action, segment class `sensitive` with a safe-default rule, `workspace` in decision records and the console; `ztx-agent enrol-workspace` and `ztx-agent workspace` start a Chromium-family browser in an erased-per-start isolated profile with fixed flags (no extensions, no sync, no QUIC or ECH, proxy-auto-config to the agent's local proxies), accept no browser flags, lock (kill the browser, erase the profile) on revocation, a failed baseline or a control plane unreachable past the grace period | done, tested with a **stub browser**, not a real Chromium. Covered: WBT-001..004, 007, 008, 010, 011, 013; WBT-005, 006 end to end (SCN-011..013). **Not done:** per-launch proxy credential (needs the extension), the workspace extension and every data control (W3: clipboard, download, upload, print, watermark), installers and updates (W4), the extension allow-list check, and every manual test (WBT-015..020). The stub-browser tests were followed by W1b with a real Chrome | policy, cp, broker, agent tests, SCN-011..013 |
| W1b | The workspace launcher run with a **real Google Chrome** (headless through a wrapper script so no window opens; SCN-014): the real browser accepted the launcher's flags, fetched a page from a private HTTP app through the proxy-auto-config, SOCKS proxy, enforcement node and connector, and the profile was erased on exit. Found and fixed: `ztx-agent workspace <start-url>` printed usage and never worked (it demanded exactly one argument) | done. Covers one Chrome version on one Linux machine, headless; not macOS, Windows, Edge or a visible window | SCN-014 |
| W2 | Inspection trust confined to the workspace (WB-003): per-tenant stable leaf key for inspection certificates, its hash offered at `GET /enrol/inspection`, the launcher passes it as Chrome's SPKI allow-list flag (never the blanket ignore-errors flag). SCN-015 with real Chrome: an inspected HTTPS page loads in the workspace; a plain Chrome profile on the same proxy shows its "Privacy error" page. Found and fixed on the way: the inspection API response had started returning the new private key | done on Linux with headless Chrome. **Not checked:** a visible window (Chrome may show a notice for the flag), the device trust store before and after, macOS, Windows, Edge. The tenant key is now as sensitive as the CA key | store, webproxy, cp, agent tests, SCN-015 |
| S5 | W3: the workspace extension (clipboard, download, upload, print, drag and drop, watermark, proxy credential, extension allow-list check) | **blocked on a decision.** Tested: Chrome 146 does not load an extension given on the command line (four variants, headless; see DESIGN D8.7), so the extension cannot be delivered by the launcher alone. Options: A bundle our own Chromium, B enterprise policy (needs administrator rights), C no extension. Not started | WBT-009, 018 |
| I12b | AI agent identities (AI-001, AI-002, basic): `POST /v1/ai-agents` creates a named identity `agent:<name>` bound to a human operator, in the group `ai-agent`, with time-limited grants to exactly the listed apps; one-time token; `ztx-agent enrol-service` enrols it with no login; it goes through the same broker and policy as people, is logged under its own name, and `DELETE /v1/ai-agents/{name}` ends access within seconds. Also fixed: enrolment tokens of one kind (connector, enforcement node, service) are now refused by the other endpoints without being used up | done, **basic**. Access also needs a `require_approval` rule for the group `ai-agent` (the grant is the approval); without one the agent gets nothing. No per-tool allow lists inside an app, no prompt or response inspection, no automatic expiry of the identity itself (only of its grants), no console tab | cp tests, SCN-010 |
| I12a | Device health (DEX-003, basic): the agent measures CPU load, memory and disk use (Linux) and sends them inside the signed posture report; the EN forwards them; `GET /v1/health` gives the latest numbers per device with plain-language findings (disk 90% or more, memory 90% or more, load 150% or more); console shows them in the Devices table | done, **Linux agents only**: macOS and Windows agents report nothing, and the console says "no report". No Wi-Fi signal, no history or trends, no thresholds an admin can change. Stored in memory. This is DEX-003 only: DEX-001 (experience scores from probes) and DEX-002 (hop-by-hop path analysis) are not started | devhealth, broker, cp tests, DEX-003 end to end |
| I11 | Admin console exercised in a real browser (Chrome) against `ztx-demo`, a lab-only demo server (plain HTTP, loopback only, seeded sample data including hostile strings) | done. All nine tabs render; sign-in, reload keeps the session, sign-out clears it, approving a request, restrict and disable buttons and the policy simulator work; hostile user names, groups and hostnames show as text and ran nothing (page title unchanged); no JavaScript errors. Found and fixed: "1 times" in the digest; the Investigate timeline repeated identical rows (now folded with a count). **Not checked:** phone-width layout, light mode, other browsers, keyboard-only use, screen readers, the Turn-inspection-on and download-certificate buttons, and a real (non-demo) deployment over HTTPS | browser walk-through |
| I10a | TLS inspection (ZIA-040, ARCH-021) and URL path and method rules (web side of ZPA-074): per-tenant intercept CA created when first enabled; the proxy decrypts CONNECT tunnels with a certificate minted per host, applies the web policy to every request, forwards upstream with full certificate verification, refuses domain fronting, honours an exempt list; the warn page now works over HTTPS; `PUT /v1/inspection`, CA download, console tab; handshake failures are logged so the admin can add exemptions | done, **basic**. No WebSocket support, no HTTP/2, no certificate-pinning handling beyond exemptions, and the CA is not installed on devices by the agent (an admin must distribute it). The CA key is sent to every enforcement node in the signed snapshot and stored in clear in the control-plane store file. No DLP, sandbox or capture on top yet. Lab flags on ztx-en weaken the SSRF guard on purpose | webproxy, store, cp, en tests, SCN-009 |
| I10b | Inline DLP on decrypted uploads (DATA-001 in basic form; request side of AI-003): six built-in detectors (credit card with Luhn, US SSN, IBAN with mod-97, AWS keys, private keys, GitHub tokens), a `dlp` rule condition, POST/PUT/PATCH bodies up to 1 MiB scanned (chunked too), a block page that names the data type, never the data; scanning only runs when a rule asks for it | done, **basic**. No exact data match, document fingerprints, OCR, machine learning, file-type extraction (a zipped or PDF upload is not opened) or response scanning. Bodies over 1 MiB are forwarded unscanned and logged as `dlp-skipped-too-large`. Pattern detectors will miss reformatted data and will sometimes flag a number that is not a card. The safe defaults contain no DLP rule. Scanner speed about 114 MB/s, worst hostile input 0.6 s per MiB | dlp, policy, webproxy tests |
| I9e | Just-in-time access with approval (ZPA-027): rule action `require_approval`; the first attempt is denied and opens a request (deduplicated, emailed when SMTP is set); an admin approves for 1 to 480 minutes, denies, or ends early; the grant travels in the signed snapshot; live sessions end when it does; console tab | done. Approval through the API, console or email notice only: there is no Slack or Teams approver and no email-reply approval. Requests are held in memory (lost on restart); grants are stored. Simulation cannot replay approval rules | approvals, policy, store, broker, cp tests, SCN-008 |
| I8e | Rule suggestions (OPS-005): `GET /v1/suggestions`, drafts to simulate and never auto-applied, and it says when the fix is the device, not the rule. Guided investigation (OPS-004): `GET /v1/investigate?user=` explains each decision in plain words with a fix | done. Rule-based text, not machine learning. The console shows suggestions (added in I9b) | advice tests |
| I8c | Insurance questionnaire evidence export: `GET /v1/evidence` (JSON or `?format=text`). It marks MFA, endpoint protection and backups as not evidenced, because this product cannot see them | done. Not mapped to any specific insurer's questionnaire | evidence tests |
| I7g | Exit-criteria review, three consecutive clean runs, lint and vulnerability scan | done: see the review below. RB1 does not meet its own exit criteria (USE-001 open) | T3.7 |

All packages pass `go vet` and `go test -race`. Fuzz targets exist for the policy loader, mux frames and posture verification.

## Known gaps and misses

- Performance: all eight targets (PERF-001..008) met on this machine (`RESULTS.md`).
- Go toolchain is pinned to go1.27.4 because go1.27.2 has two standard-library vulnerabilities that affect this code.
- **Design deviation:** certificate renewal uses the current valid device certificate over mTLS, not an IdP refresh token (DESIGN D4.2). A stolen but unrevoked certificate can therefore renew itself indefinitely until the admin revokes it or disables the user. Fix: cap renewal chains (for example 7 days) or require a fresh IdP token.
- **Design deviation:** ENs poll a full snapshot from the control plane every few seconds instead of holding a push stream (DESIGN D2.6). Fine for small tenants, not for scale. The snapshot carries every user and policy for every tenant, so an EN certificate can read all tenants: ENs are platform-trusted.
- The binaries now run together in `test/e2e` (cp, en, connector, agent, with the in-process test IdP and a fake posture toolchain on PATH). The connector only uses the first `--en` address (no EN failover yet).
- Alerts, decision history, access requests and risk scores live in control-plane memory and are lost on restart (grants and restrictions are stored). Alerts are delivered through the API, the console and email; the weekly digest exists. Email has only been tested against a fake SMTP server.
- Connector and EN certificates last 7 days and have no renewal in RB1.
- Agent: Windows firewall posture probe is not implemented (stays unknown, so policies requiring it fail closed). No installers, tunnel driver or auto-update. The browser is launched by the caller (`openURL`), the CLI wiring comes with I5d.
- Audit log: truncating the tail is not detectable from the file alone.
- Posture probe parsers are tested on inline samples, not real captured output.
- Web proxy sees host names only (no TLS inspection), and `warn` cannot be shown on HTTPS.
- Test plan items not yet implemented: soak and failure injection (RES-001..005, 007), SCN-003, 005 and 006, usability checks (USE), the 30-minute nightly fuzz budget.

## Scope changes to know about

- Requirements v0.5 made inspection, DLP, ZPA extras, browser isolation and BYOD, risk scoring, DEX, AI controls and several SMB operations **Must**. RB1 scope was **not** widened, so these are still outside the build. They are tracked in `ROADMAP.md`. TLS inspection is now on by default in the requirements, which closes design question 4 in favour of decryption, but the design for it is not written yet.

## Open decisions needing the user

1. Whether RB1 should grow to include any of the newly-Must items (browser isolation is the one asked about). Default if unanswered: no.
2. Patent review of connector stitching before any commercial use (REQUIREMENTS section 15).

## RB1 exit criteria (TEST-PLAN.md T3.7), reviewed 2026-11-15

| # | Criterion | State |
|---|---|---|
| 1 | All P1 tests pass on three consecutive nightly runs | Three consecutive rounds passed on the committed tree (unit and component tests with `-race`, then 20 end-to-end tests with the real binaries, about 60 s each). These were back-to-back runs on one machine, not nightly CI: there is no CI configured |
| 2 | No open S1 or S2 defect | No known open defect. This is not an independent review: there has been no external penetration test or code audit, and I wrote both the code and the tests |
| 3 | Every P2 failure has an owner and a decision | No P2 test fails. P2 items not run or not built are listed in RESULTS.md with their state |
| 4 | Design-target misses are listed | All eight PERF targets are met on this machine, one machine only. No misses to list |
| 5 | Traceability has no requirement in RB1 scope without tests | 169 of 172 test-plan IDs have a test or recorded result. The 3 without are USE-001..003. Separately, the plan's coverage table (T3.5) states known gaps per requirement, and the not-built items below mean some requirements are covered only partly |
| 6 | `govulncheck` clean, dependencies reviewed | `govulncheck` reports no vulnerabilities on go1.27.4; `go vet` and `staticcheck` are clean. There are no third-party Go dependencies (standard library only), so there is nothing else to review |
| 7 | USE-001 done by at least two people who did not write the product | **Not met.** It needs people. Not something I can do |

**RB1 does not meet its own exit criteria**: criterion 7 is open, criterion 1 uses back-to-back runs on one machine rather than nightly CI, and criterion 2 has no independent review behind it.

### Not built that the design or test plan expected


- Of the 34 items promoted to Must in v0.5, twelve are built, in simple form: weekly digest (ADM-009), insurance evidence export (SMB-004), policy simulation (ZPA-028, ADM-020), rule suggestions and guided investigation (OPS-005, OPS-004), restricted group (ZPA-072), just-in-time approval (ZPA-027), a basic risk score (ARCH-007) basic TLS inspection (ZIA-040) device health (DEX-003) and basic AI agent identities (AI-001, AI-002). AI-003 is a quarter done (request-side pattern DLP, which an admin can aim at AI tools with a category rule). ZPA-074 is half done (URL path and method rules on inspected web traffic, nothing for private apps). **The other 21 are not built**: what should sit on top of inspection (ZIA-022b/c, ZIA-031, ZIA-034, DLP in DATA-005/006, AGT-014, AI-003), browser isolation and BYOD (ZIA-022d, ZIA-024, ZPA-055, BYOD-001..004), private service edge and business continuity (ZPA-043, ZPA-044), first-packet enforcement (ZPA-073) and digital experience monitoring beyond device health (DEX-001, DEX-002). See ROADMAP.md.
- Everything in ROADMAP.md.
