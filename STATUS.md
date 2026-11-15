# Status

**Last updated:** 2026-11-15, after I5b-1 (OIDC ID-token verifier).
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
| I5b-2 | Device and connector enrolment endpoints (cert issuance) | **next** | AG-001..004, AG-014, PKI |
| I5c | Agent (local proxies, posture probes, renewal) | pending | AG |
| I5d | `cmd/` binaries for cp, en, connector, agent | pending | |
| I6 | End-to-end scenarios, alerts, run instructions | pending | SCN, ALR |

All packages pass `go vet` and `go test -race`. Fuzz targets exist for the policy loader, mux frames and posture verification.

## Known gaps and misses

- **PERF-005 missed:** policy evaluation about 59 us for 500 rules against a 50 us target. Fix is an index by group and app. Details in `RESULTS.md`.
- Audit log: truncating the tail is not detectable from the file alone.
- Posture probe parsers are tested on inline samples, not real captured output.
- Web proxy sees host names only (no TLS inspection), and `warn` cannot be shown on HTTPS.
- Test plan items not yet implemented: L4 end-to-end with real binaries, load and soak (PERF, RES), most USE checks, alerts (ALR).

## Scope changes to know about

- Requirements v0.5 made inspection, DLP, ZPA extras, browser isolation and BYOD, risk scoring, DEX, AI controls and several SMB operations **Must**. RB1 scope was **not** widened, so these are still outside the build. They are tracked in `ROADMAP.md`. TLS inspection is now on by default in the requirements, which closes design question 4 in favour of decryption, but the design for it is not written yet.

## Open decisions needing the user

1. Whether RB1 should grow to include any of the newly-Must items (browser isolation is the one asked about). Default if unanswered: no.
2. Patent review of connector stitching before any commercial use (REQUIREMENTS section 15).
