# Implementation results and target misses

Running log for RB1 (TEST-PLAN.md T3.7 item 4). Machine: Linux 6.8, 12 threads, Go 1.27.4. Dated 2026-11-15.

## Performance targets (DESIGN.md D3.7)

All components of the private path run in one process on loopback unless noted, so these are optimistic for latency and pessimistic for throughput (agent, two TLS hops and the echo app share the CPU).

| ID | Target | Measured | Status |
|---|---|---|---|
| PERF-001 session setup | p95 under 20 ms | p50 0.93 ms, p95 1.4 ms, p99 1.8 ms | met |
| PERF-002 single-stream throughput | at least 500 Mbit/s | 616 Mbit/s one way (362 originally; 460 after raising the mux frame size to 60 KiB; 616 after reusing read and write buffers) | met |
| PERF-003 1000 concurrent sessions | heap under 300 MB, no errors | 1000 held, 0 errors, heap +131 MB (whole stack in one process, so an upper bound for the EN) | met |
| PERF-004 connector idle memory | under 30 MB | 9.9 MB resident after 10 s idle (real process) | met |
| PERF-005 / POL-028 policy evaluation | under 50 us for 500 rules | 0.36 us (was 59 us with a linear scan; rules are now indexed by group and user, and a randomized test checks the index never changes a decision) | met |
| PERF-006 policy push to 20 ENs | all within 5 s | 1.9 s worst case with 20 pollers and a 2 s interval. The default interval was 5 s, which would not have met the target, so it is now 2 s | met |
| PERF-007 web proxy throughput | 1000 requests/s per core | 2355 req/s on one core with client, proxy and origin sharing it (885 before caching the per-request certificate-chain check; revocation is still checked on every request) | met |
| PERF-008 decision-log overhead | under 5% | within noise: best-of-three 1.016 ms without log, 0.967 ms with (negative, so no measurable cost) | met |

Reproduce: `go test -tags perf -v -run TestPerf ./internal/broker ./internal/en ./internal/webproxy` and `go test -tags e2e -run TestPerf004 ./test/e2e`.

## Security checks

| ID | Result |
|---|---|
| SEC-017 `govulncheck` | Clean on go1.27.4. On go1.27.2 it found two standard-library vulnerabilities (GO-2026-6859 `net/http` MaxBytesReader header race, GO-2026-6809), so `go.mod` pins `toolchain go1.27.4` |
| SEC-018 race detector | All unit, component and end-to-end tests pass with `-race` |
| SEC-019 fuzzing | 30 s each, no crash: policy loader, mux frames, posture verification. The 30-minute nightly budget in the plan has not been run |
| `staticcheck` | Not run (not installed here) |

## Known gaps found while implementing

- **Audit log tail truncation is not detectable** from the file alone (a shorter chain is still valid). Mitigation: store the head hash outside the log. `TestTamperDetected/truncate` documents the behaviour.
- The mux accept queue is sized to `MaxStreams`. A burst above that is rejected `busy`, by design.
- Probe parsers use inline samples. Golden files from real machines (POS-004) are still to be collected.
- Certificate renewal uses the current certificate over mTLS instead of an IdP refresh token (DESIGN D4.2).
- Enforcement nodes poll full snapshots instead of receiving pushes (DESIGN D2.6).

## Resilience (TEST-PLAN.md T3.2)

| ID | Result |
|---|---|
| RES-001 EN killed and restarted | Real processes: the live session breaks, the connector and agent recover on their own, access again 0.2 s after the restart (target 30 s). Component test: connector reconnects after its link is cut. `test/e2e` `TestRes001ENRestart` |
| RES-002 latency and loss | 100 ms added each way: sessions open and move 256 KiB correctly. **Packet loss was not simulated**: it needs kernel support (tc netem) and root |
| RES-003 reset mid-frame | 20 cuts at different byte offsets, including mid-handshake and mid-frame: the EN keeps serving, no leaked sessions, goroutines return to baseline |
| RES-004 disk full on connector host | **Not tested.** The connector writes nothing at run time, so the risk is low, but it is unproven |
| RES-005 clock jump | Not injected into a live system (cannot change the host clock). Covered by unit tests: certificates not yet valid or expired are refused (`TestExpiryAndTolerance`), posture reports dated in the future or too old fail closed (`TestPostureFailClosed`) |
| RES-006 corrupt agent files | Covered earlier (`TestCorruptStateRecovers`) |
| RES-007 24 h soak, 200 sessions | **Shortened.** 3 minutes, 200 workers, 720,593 sessions, 0 errors, goroutines 1661 to 1534 and heap 53 to 49 MiB (both slightly down). A first run showed +187% heap, which was the test rig's own record keeper and not the product; the soak now disables it. `SOAK_SECONDS=86400` runs the full version |

## Test-plan coverage (checked mechanically on 2026-11-15)

Every ID in TEST-PLAN.md was searched for in the test code. 169 of 172 are referenced by a test or a recorded result. The three that are not are the usability checks (USE-001..003), which need people.

Added in I7f because the check found them missing or unlabelled: VAL-009 shadow warning, the 20-valid and 30-invalid policy corpora (VAL-010, VAL-011), FUZ-005, SEC-001, SEC-003, SEC-009 (no secrets in any process output or log file), SEC-011 (old TLS refused), SEC-012 (per-identity connection limit, new), SEC-014 (new sessions refused while the decision log cannot be written, new), SEC-015, AG-011 (minimum agent version, new), AG-012, AG-013, CP-007, CP-008, CP-011 (cursor pagination, new), PA-008, PA-015, PA-016, WEB-013, WEB-014.

Not done or only partly done, stated plainly:

| Item | State |
|---|---|
| USE-001, USE-002, USE-003 | **Not done.** They need people who did not write the product (two for USE-001). The 30-minute target is unproven. The scripted day-one flow takes about 2 s, but that excludes every manual step |
| SEC-007 policy tampering | Met in I9a: state is signed by the control plane and verified by a pinned key; unsigned, forged, tampered, replayed and stale state are refused. The signing key is a file (no KMS or HSM) |
| SEC-014 disk full | The sink-health mechanism is tested with a fake sink. A real full disk was not simulated |
| RES-002 packet loss, RES-004 | Not simulated (see the resilience table) |
| RES-007 | 3 minutes, not 24 hours |
| SEC-019 | 30 s per fuzz target, not 30 minutes |
| `/v1/decisions` search | Built in I8a (in-memory, bounded, lost on restart) |
| Policy signing, `/v1/decisions`, admin console | Built in I9a, I8a and I9b. The console was checked by hand in Chrome in I11 (see STATUS.md for what that did and did not cover) |

## Flaky test found and fixed (I16 regression)

`TestHealthRidesInTheSignedPostureReport` failed once in a full run (passed 15 of 15 alone). Cause: the enforcement node acknowledged a posture report and only then logged the posture and health events, so a reader that acted on the acknowledgement could look too early. Fixed in the product, not only the test: events are now recorded before the acknowledgement (the same record-first principle used for denials), and the test also waits for the record.

## Test races fixed after the capture regression

- `TestScn016DeveloperToolsThroughInspection` failed once in a full run: it ran curl straight after enabling inspection, before the enforcement node had synced the setting, so curl saw an uninspected tunnel. It now waits until inspection is in effect.
- `TestScn015` had a control that proved only that Chrome rejected some certificate. It now also requires the proxy's own record that a plain browser was shown, and refused, the inspection certificate.
