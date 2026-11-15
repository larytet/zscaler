.PHONY: build test race vet fuzz e2e vuln docker-build real
build:
	go build -o bin/ ./cmd/...
vet:
	go vet ./...
test:
	go test ./...
race:
	go test -race -count=1 ./...
fuzz:
	go test ./internal/policy -run xxx -fuzz FuzzParse -fuzztime 30s
	go test ./internal/mux -run xxx -fuzz FuzzFrames -fuzztime 30s
	go test ./internal/posture -run xxx -fuzz FuzzVerify -fuzztime 30s
e2e:
	go test -race -count=1 -tags e2e ./test/e2e/...
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

# Build the binaries inside a Go container, with no Go installation on this machine (needs Docker).
GOIMAGE ?= golang:$(shell sed -n 's/^toolchain go//p' go.mod)
docker-build:
	mkdir -p bin
	docker run --rm --user $$(id -u):$$(id -g) -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
		-v $$PWD:/src -w /src $(GOIMAGE) go build -o bin/ ./cmd/...

# Real-environment tests on a Linux node with Kubernetes: ZTX_TEST_NODE=<username>@<servername> make real
real:
	test/real/run.sh run
