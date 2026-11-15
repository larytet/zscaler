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
