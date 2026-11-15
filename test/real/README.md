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
| Tools | `rsync`, `docker`, `kubectl`, `curl`, `python3`. No Go installation is needed |
| Cluster | A running Kubernetes cluster that `kubectl` on the node can reach (a one-node kind cluster is enough) |
| Building | The code is built **inside a Docker container**: image `golang:<version named in go.mod>` (override with `ZTX_BUILD_IMAGE`), about 1.3 GB, pulled once by `run.sh setup`. The container runs as your user, so nothing on the node is owned by root |
| Network | The node can reach its own cluster. Outbound internet is needed only to pull the build image once, and by the tests that say they need it (those are skipped, with the reason printed, if it is missing) |

## How to run

```sh
export ZTX_TEST_NODE=<username>@<servername>      # never committed
# optional: ZTX_TEST_KUBECTL="sudo kubectl"  ZTX_TEST_DOCKER="sudo docker"
test/real/run.sh setup        # once: pulls the Go build image onto the node
test/real/run.sh run          # builds in a container, runs the REAL- tests on the node, records the result
test/real/run.sh run 'PA'     # only tests whose name matches
test/real/run.sh clean        # removes leftovers of earlier runs, by label, and nothing else
```

## What a run touches

- One namespace named `ztx-real-<run id>`, labelled `app.kubernetes.io/part-of=ztx-real-test`, created and deleted
  by the run. No other namespace, no cluster-wide object.
- `~/ztx-real/` on the node (source, binaries, Go build cache) and container images tagged `ztx-real-<run id>`.
- Results are appended to `RESULTS-REAL.md` (date, commit, the node's operating system and core count, counts).
  The node's name is never written to a file in the repository.
