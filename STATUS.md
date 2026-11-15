# Status

**Last updated:** 2026-11-15, after I8e (suggestions and investigation).
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
| I8e | Rule suggestions (OPS-005): `GET /v1/suggestions`, drafts to simulate and never auto-applied, and it says when the fix is the device, not the rule. Guided investigation (OPS-004): `GET /v1/investigate?user=` explains each decision in plain words with a fix | done. Rule-based text, not machine learning. No admin UI to show it in | advice tests |
| I8c | Insurance questionnaire evidence export: `GET /v1/evidence` (JSON or `?format=text`). It marks MFA, endpoint protection and backups as not evidenced, because this product cannot see them | done. Not mapped to any specific insurer's questionnaire | evidence tests |
| I7g | Exit-criteria review, three consecutive clean runs, lint and vulnerability scan | done: see the review below. RB1 does not meet its own exit criteria (USE-001 open) | T3.7 |

All packages pass `go vet` and `go test -race`. Fuzz targets exist for the policy loader, mux frames and posture verification.

## Known gaps and misses

- Performance: all eight targets (PERF-001..008) met on this machine (`RESULTS.md`).
- Go toolchain is pinned to go1.27.4 because go1.27.2 has two standard-library vulnerabilities that affect this code.
- **Design deviation:** certificate renewal uses the current valid device certificate over mTLS, not an IdP refresh token (DESIGN D4.2). A stolen but unrevoked certificate can therefore renew itself indefinitely until the admin revokes it or disables the user. Fix: cap renewal chains (for example 7 days) or require a fresh IdP token.
- **Design deviation:** ENs poll a full snapshot from the control plane every few seconds instead of holding a push stream (DESIGN D2.6). Fine for small tenants, not for scale. The snapshot carries every user and policy for every tenant, so an EN certificate can read all tenants: ENs are platform-trusted.
- The binaries now run together in `test/e2e` (cp, en, connector, agent, with the in-process test IdP and a fake posture toolchain on PATH). The connector only uses the first `--en` address (no EN failover yet).
- Alerts live in control-plane memory (lost on restart). Delivery is the API plus email on a new alert; there is no UI page, and the weekly digest (ADM-009, now Must) is not built. Email has only been tested against a fake SMTP server.
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

- CP-signed policy stream (DESIGN D5.5, SEC-007): ENs trust any authenticated control plane. Rollback to an older version is refused.
- The admin UI (DESIGN D5.2) is not built: API only.
- Of the 34 items promoted to Must in v0.5, only the cheap operations ones are built, in simple form: weekly digest, insurance evidence export, private-access policy simulation, rule suggestions, guided investigation. The other 29 are not (inspection add-ons, DLP, ZPA extras, isolation and BYOD, risk scoring, DEX, AI controls, and others). See ROADMAP.md.
- Everything in ROADMAP.md.
