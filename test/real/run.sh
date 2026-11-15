#!/bin/sh
# Runs the real-environment tests (TEST-PLAN.md T7) on a Linux test node.
#
#   ZTX_TEST_NODE=<username>@<servername> test/real/run.sh [run|clean] [go test -run pattern]
#
# The node needs ssh key access, passwordless sudo, rsync, docker and a reachable Kubernetes cluster.
# Nothing is built with a Go installation on the node: the code is built inside a Docker container
# (image golang:<version from go.mod>, or ZTX_BUILD_IMAGE), and the compiled test binary is run on
# the node. Nothing about the node is kept in the repository: it is given only through the environment.
set -eu
cd "$(dirname "$0")/../.."
: "${ZTX_TEST_NODE:?set ZTX_TEST_NODE to <username>@<servername> (see TEST-PLAN.md T7.2)}"
cmd="${1:-run}"; shift || true
pattern="${1:-.}"
ssh_="ssh -o BatchMode=yes -o ConnectTimeout=20 $ZTX_TEST_NODE"
GOVER="$(sed -n 's/^toolchain go//p' go.mod)"
BUILD_IMAGE="${ZTX_BUILD_IMAGE:-golang:$GOVER}"
DOCKER="${ZTX_TEST_DOCKER:-sudo docker}"

case "$cmd" in
clean)
  # removes leftovers of earlier runs by their label, and nothing else
  $ssh_ "${ZTX_TEST_KUBECTL:-sudo kubectl} delete namespace -l app.kubernetes.io/part-of=ztx-real-test --wait=true --timeout=180s || true"
  exit 0;;
setup)
  # fetches the build image onto the node (once); there is no Go to install
  $ssh_ "$DOCKER pull $BUILD_IMAGE"
  exit 0;;
run) ;;
*) echo "usage: $0 [run|clean|setup] [test name pattern]" >&2; exit 2;;
esac

$ssh_ 'mkdir -p ~/ztx-real/src ~/ztx-real/logs'
rsync -az --delete --exclude .git --exclude bin --exclude docs --exclude '*.log' -e "ssh -o BatchMode=yes" ./ "$ZTX_TEST_NODE":ztx-real/src/
stamp="$(date +%Y%m%d-%H%M%S)"
commit="$(git rev-parse --short HEAD)"
log="test/real/last-run.log"
set +e
# build in a container as the node user (so the files are not root-owned): the binaries for the
# product and one compiled test binary. CGO is off so they are static.
$ssh_ "mkdir -p ~/ztx-real/bin ~/ztx-real/cache && $DOCKER run --rm --user \$(id -u):\$(id -g) -e HOME=/tmp -e GOCACHE=/cache/build -e GOPATH=/cache/gopath -e GOTOOLCHAIN=local -e CGO_ENABLED=0 -v \$HOME/ztx-real/src:/src -v \$HOME/ztx-real/bin:/out -v \$HOME/ztx-real/cache:/cache -w /src $BUILD_IMAGE sh -c 'go build -o /out/ ./cmd/... ./test/real/echoapp ./test/real/originapp && go test -c -tags real -o /out/real.test ./test/real'" 2>&1 | tee "$log" &&
$ssh_ "cd ~/ztx-real && ZTX_BIN=\$HOME/ztx-real/bin ZTX_TEST_KUBECTL='${ZTX_TEST_KUBECTL:-sudo kubectl}' ZTX_TEST_DOCKER='$DOCKER' ./bin/real.test -test.v -test.count=1 -test.timeout 30m -test.run '$pattern'" 2>&1 | tee -a "$log"
status=$?
set -e
pass=$(grep -c '^--- PASS' "$log" || true); fail=$(grep -c '^--- FAIL' "$log" || true); skip=$(grep -c '^--- SKIP' "$log" || true)
os=$($ssh_ 'uname -sr; nproc' | tr '\n' ' ')
[ -f RESULTS-REAL.md ] || printf '# Real-environment test results (TEST-PLAN.md T7)\n\nOne line per run of test/real/run.sh: date, commit, the node'"'"'s operating system and core count (never its name), and the counts. A failure stays listed.\n\n' > RESULTS-REAL.md
echo "- $stamp, commit $commit, node: $os: $pass passed, $fail failed, $skip skipped" >> RESULTS-REAL.md
echo "REAL tests: $pass passed, $fail failed, $skip skipped (log: $log)"
[ "$fail" = 0 ] && grep -q '^ok\|^PASS' "$log"
