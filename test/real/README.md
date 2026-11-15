# Real-environment tests: what the test node must provide

These tests (TEST-PLAN.md section T7) run the product's real binaries on a Linux machine with a Kubernetes
cluster. The person running them provides the machine. This file is the checklist.

## System requirements of the test node

| Need | Detail |
|---|---|
| Access | `ssh <username>@<servername>` works with a key. No password prompt. |
| Privilege | `sudo` works without a password. It is used only for `docker` and `kubectl`. |
| Operating system | Linux, x86-64 |
| Size | At least 4 CPUs and 8 GB of free memory; a few GB of free disk |
| Tools | `rsync`, `docker`, `kubectl`, `curl`, `python3` |
| Cluster | A running Kubernetes cluster that `kubectl` on the node can reach (a one-node kind cluster is enough) |
| Go | Not needed beforehand: `run.sh setup` installs the Go version named in `go.mod` under `~/ztx-real/go` on the node, after checking the published checksum |
| Network | The node can reach its own cluster. Outbound internet is needed only to install Go once, and by the tests that say they need it (those are skipped, with the reason printed, if it is missing) |

## How to run

```sh
export ZTX_TEST_NODE=<username>@<servername>      # never committed
# optional: ZTX_TEST_KUBECTL="sudo kubectl"  ZTX_TEST_DOCKER="sudo docker"
test/real/run.sh setup        # once: installs Go on the node
test/real/run.sh run          # builds on the node, runs the REAL- tests, records the result
test/real/run.sh run 'PA'     # only tests whose name matches
test/real/run.sh clean        # removes leftovers of earlier runs, by label, and nothing else
```

## What a run touches

- One namespace named `ztx-real-<run id>`, labelled `app.kubernetes.io/part-of=ztx-real-test`, created and deleted
  by the run. No other namespace, no cluster-wide object.
- `~/ztx-real/` on the node (source, binaries, Go, logs) and container images tagged `ztx-real-<run id>`.
- Results are appended to `RESULTS-REAL.md` (date, commit, the node's operating system and core count, counts).
  The node's name is never written to a file in the repository.
