# whyreach — keep these targets in sync with the "Commands" section of CLAUDE.md.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
CROSS_TARGETS := darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
GORELEASER := github.com/goreleaser/goreleaser/v2@v2.19.0

.PHONY: build test lint vuln lab lab-desktop lab-agent lab-bench lab-realcases lab-root golden cross release-check release-snapshot release clean

## build: static binary in bin/whyreach
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/whyreach ./cmd/whyreach

## test: unit tests and rule fixtures (no Docker, no root, no network)
test:
	go test ./...

## lint: golangci-lint v2 (config in .golangci.yml)
lint:
	golangci-lint run

## vuln: known vulnerabilities in code we actually call, standard library included (needs network)
vuln:
	go run $(GOVULNCHECK) ./...

## lab: failure-lab scenarios in test/lab against Docker (never cached)
lab:
	go test -tags lab -count=1 ./test/e2e/...

## lab-desktop: the lab with whyreach behind a Docker API proxy whose /version
## says Docker Desktop, so it reads every listener in a probe container: a
## rehearsal on Docker Engine of the run on Docker Desktop's WSL integration
## (docs/adr/0004-wsl2.md)
lab-desktop:
	go test -tags lab -count=1 ./test/e2e/... -args -lab.desktop

## lab-agent: a headless Claude Code agent diagnoses each lab scenario through
## whyreach's MCP tools alone (needs Docker, the claude CLI and model access)
lab-agent:
	go test -tags lab,agent -count=1 -run TestAgent -timeout 60m -v ./test/e2e/...

## lab-bench: the agent benchmark (INITIAL.md §6.4): for each lab scenario, a
## headless Claude Code with a shell only (sandboxed by bwrap, a read-only Docker
## proxy and a guard hook) and one with whyreach's four MCP tools only; masked
## results in bin/bench/ (needs Docker, bwrap, the claude CLI and model access;
## about 15 minutes and $0.13 on Claude Haiku; docs/research/agent-benchmark.md)
lab-bench:
	go test -tags lab,agent,bench -count=1 -run TestBench -timeout 240m -v ./test/e2e/...

## lab-realcases: the real-case check (docs/research/real-cases.md): broken
## setups from Stack Overflow, the Docker forums and GitHub issues, rebuilt in
## test/realcases/; checks each fails as its asker said, then runs whyreach with
## probe containers on and off; masked results in bin/realcases/ (needs Docker
## and the cases' official images, which it never pulls)
lab-realcases:
	go test -tags lab,realcases -count=1 -run TestRealCases -timeout 60m -v ./test/e2e/...

## lab-root: the lab as root, where whyreach enters the containers' network
## namespaces itself (the netns executor): every scenario, and no Docker
## writes; plus the executor's root-only test. Everything is built as you
## first; only the test binaries run as root (sudo asks for your password).
LAB_ROOT := $(CURDIR)/bin/lab-root
lab-root:
	@mkdir -p $(LAB_ROOT)
	CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=lab' -o $(LAB_ROOT)/whyreach ./cmd/whyreach
	CGO_ENABLED=0 go build -trimpath -o $(LAB_ROOT)/labserver ./test/labserver
	go test -c -o $(LAB_ROOT)/executor.test ./internal/executor
	go test -c -tags lab,privileged -o $(LAB_ROOT)/e2e.test ./test/e2e
	cd internal/executor && sudo $(LAB_ROOT)/executor.test -test.run 'Netns|ReadInRoot' -test.count=1 -test.v
	cd test/e2e && sudo $(LAB_ROOT)/e2e.test -test.run 'TestLabNetns' -test.count=1 -test.v -test.timeout 30m \
		-lab.bin $(LAB_ROOT)/whyreach -lab.server $(LAB_ROOT)/labserver

## golden: regenerate golden files: the text renderer, the compact MCP structured form, the Diagnosis JSON, the MCP tools
golden:
	go test ./internal/report/... ./internal/mcpserver/... -update

## release-check: validate .goreleaser.yaml (go run fetches the pinned goreleaser first)
release-check:
	go run $(GORELEASER) check

## release-snapshot: the release archives and checksums.txt in dist/, as a tag would make
## them, publishing nothing; the image is left to the release workflow
release-snapshot:
	go run $(GORELEASER) release --snapshot --clean --skip=docker

## release: what .github/workflows/release.yml runs on a v* tag (it publishes); refuses to run elsewhere
release:
	@test -n "$${GITHUB_ACTIONS:-}" || { echo "make release runs only in the release workflow; use make release-snapshot" >&2; exit 1; }
	go run $(GORELEASER) release --clean

## cross: compile check for macOS and Windows (INITIAL.md §4.15)
cross:
	@for t in $(CROSS_TARGETS); do \
		echo "go build ./... for $$t"; \
		GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build -o /dev/null ./...; \
	done

clean:
	rm -rf bin dist spikes/out
