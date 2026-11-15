# Status

**Last updated:** 2026-11-15, after I5d-2 (command-line binaries).
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
| I6a | End-to-end test starting the real binaries (SCN-001..004) | **next** | SCN |
| I6b | Alerts and plain-language summaries | pending | ALR |
| I6c | Run instructions in README, load and soak tools | pending | PERF, RES |

All packages pass `go vet` and `go test -race`. Fuzz targets exist for the policy loader, mux frames and posture verification.

## Known gaps and misses

- **PERF-005 missed:** policy evaluation about 59 us for 500 rules against a 50 us target. Fix is an index by group and app. Details in `RESULTS.md`.
- **Design deviation:** certificate renewal uses the current valid device certificate over mTLS, not an IdP refresh token (DESIGN D4.2). A stolen but unrevoked certificate can therefore renew itself indefinitely until the admin revokes it or disables the user. Fix: cap renewal chains (for example 7 days) or require a fresh IdP token.
- **Design deviation:** ENs poll a full snapshot from the control plane every few seconds instead of holding a push stream (DESIGN D2.6). Fine for small tenants, not for scale. The snapshot carries every user and policy for every tenant, so an EN certificate can read all tenants: ENs are platform-trusted.
- The `cmd/` binaries are compiled but have never been run together; I6a is where that gets proved. The connector only uses the first `--en` address (no EN failover yet).
- Connector and EN certificates last 7 days and have no renewal in RB1.
- Agent: Windows firewall posture probe is not implemented (stays unknown, so policies requiring it fail closed). No installers, tunnel driver or auto-update. The browser is launched by the caller (`openURL`), the CLI wiring comes with I5d.
- Audit log: truncating the tail is not detectable from the file alone.
- Posture probe parsers are tested on inline samples, not real captured output.
- Web proxy sees host names only (no TLS inspection), and `warn` cannot be shown on HTTPS.
- Test plan items not yet implemented: L4 end-to-end with real binaries, load and soak (PERF, RES), most USE checks, alerts (ALR).

## Scope changes to know about

- Requirements v0.5 made inspection, DLP, ZPA extras, browser isolation and BYOD, risk scoring, DEX, AI controls and several SMB operations **Must**. RB1 scope was **not** widened, so these are still outside the build. They are tracked in `ROADMAP.md`. TLS inspection is now on by default in the requirements, which closes design question 4 in favour of decryption, but the design for it is not written yet.

## Open decisions needing the user

1. Whether RB1 should grow to include any of the newly-Must items (browser isolation is the one asked about). Default if unanswered: no.
2. Patent review of connector stitching before any commercial use (REQUIREMENTS section 15).
