# Implementation results and target misses

Running log for RB1 (see TEST-PLAN.md T3.7 item 4). Machine: Linux 6.8, 12 threads, Go 1.27.

| Date | ID | Target | Measured | Status |
|---|---|---|---|---|
| 2026-11-15 | PERF-005 / POL-028 | under 50 us for 500 rules | about 59 us (worst case: matching rule is last, linear scan) | **Miss.** Fix when needed: index rules by group and app at compile time |

## Implementation subtasks

| ID | Subtask | Status |
|---|---|---|
| I1 | Policy engine, validation, unit and fuzz tests | done |
| I2 | PKI, posture, mux, audit packages | done |
| I3 | Enforcement node: broker and connector | done |
| I4 | Web proxy and classification | pending |
| I5 | Control plane (store, API, safe defaults), agent, IdP | pending |
| I6 | End-to-end scenarios, alerts, README run instructions | pending |

## Known gaps found while implementing

- **Audit log tail truncation is not detectable** from the file alone (a shorter chain is still valid). Mitigation for later: store the head hash outside the log (CP database or signed checkpoint). Test `TestTamperDetected/truncate` documents the behaviour.
- **mux accept queue** is now sized to `MaxStreams`. A burst above that is rejected `busy`, by design.
- Probe parsers use inline samples. Golden files from real machines (POS-004) are still to be collected.
