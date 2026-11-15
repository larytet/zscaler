#!/bin/sh
# Runs the real-environment tests (TEST-PLAN.md T7) on a Linux test node.
#
#   ZTX_TEST_NODE=<username>@<servername> test/real/run.sh [run|clean] [go test -run pattern]
#
# The node needs ssh key access, passwordless sudo, rsync, docker and a reachable Kubernetes cluster.
# Go is installed under ~/ztx-real/go on the node by `setup` if it is not there. Nothing about the
# node is kept in the repository: it is given only through the environment.
set -eu
cd "$(dirname "$0")/../.."
: "${ZTX_TEST_NODE:?set ZTX_TEST_NODE to <username>@<servername> (see TEST-PLAN.md T7.2)}"
cmd="${1:-run}"; shift || true
pattern="${1:-.}"
ssh_="ssh -o BatchMode=yes -o ConnectTimeout=20 $ZTX_TEST_NODE"
GOVER="$(sed -n 's/^toolchain go//p' go.mod)"
remote_go='$HOME/ztx-real/go/bin/go'

case "$cmd" in
clean)
  # removes leftovers of earlier runs by their label, and nothing else
  $ssh_ "${ZTX_TEST_KUBECTL:-sudo kubectl} delete namespace -l app.kubernetes.io/part-of=ztx-real-test --wait=true --timeout=180s || true"
  exit 0;;
setup)
  $ssh_ "set -e; mkdir -p ~/ztx-real; cd ~/ztx-real; [ -x go/bin/go ] && go/bin/go version && exit 0
    curl -fsSL 'https://go.dev/dl/?mode=json&include=all' -o dl.json
    SHA=\$(python3 -c \"import json
for r in json.load(open('dl.json')):
    if r['version']=='go$GOVER':
        for f in r['files']:
            if f['os']=='linux' and f['arch']=='amd64' and f['kind']=='archive': print(f['sha256'])\")
    curl -fsSL https://go.dev/dl/go$GOVER.linux-amd64.tar.gz -o go.tgz
    echo \"\$SHA  go.tgz\" | sha256sum -c -
    rm -rf go && tar -xzf go.tgz && rm -f go.tgz dl.json && go/bin/go version"
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
$ssh_ "cd ~/ztx-real/src && export PATH=\$HOME/ztx-real/go/bin:\$PATH GOTOOLCHAIN=local ZTX_TEST_KUBECTL='${ZTX_TEST_KUBECTL:-sudo kubectl}' ZTX_TEST_DOCKER='${ZTX_TEST_DOCKER:-sudo docker}' && go build -o ~/ztx-real/bin/ ./cmd/... && go test -tags real -count=1 -v -timeout 30m -run '$pattern' ./test/real" 2>&1 | tee "$log"
status=$?
set -e
pass=$(grep -c '^--- PASS' "$log" || true); fail=$(grep -c '^--- FAIL' "$log" || true); skip=$(grep -c '^--- SKIP' "$log" || true)
os=$($ssh_ 'uname -sr; nproc' | tr '\n' ' ')
[ -f RESULTS-REAL.md ] || printf '# Real-environment test results (TEST-PLAN.md T7)\n\nOne line per run of test/real/run.sh: date, commit, the node'"'"'s operating system and core count (never its name), and the counts. A failure stays listed.\n\n' > RESULTS-REAL.md
echo "- $stamp, commit $commit, node: $os: $pass passed, $fail failed, $skip skipped" >> RESULTS-REAL.md
echo "REAL tests: $pass passed, $fail failed, $skip skipped (log: $log)"
[ "$fail" = 0 ] && grep -q '^ok\|^PASS' "$log"
