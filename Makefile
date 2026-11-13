# whyreach — keep these targets in sync with the "Commands" section of CLAUDE.md.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
CROSS_TARGETS := darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: build test lint vuln lab lab-root golden cross clean

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

## lab: failure-lab scenarios against Docker (arrive in M1)
lab:
	@if [ -d test/e2e ]; then go test -tags lab ./test/e2e/...; \
	else echo "lab: no scenarios yet (they arrive in M1)"; fi

## lab-root: lab scenarios that need root (netns executor)
lab-root:
	@if [ -d test/e2e ]; then sudo -E env "PATH=$$PATH" go test -tags lab,privileged ./test/e2e/...; \
	else echo "lab-root: no scenarios yet (they arrive in M1)"; fi

## golden: regenerate golden files for the renderers
golden:
	@if [ -d internal/report ]; then go test ./internal/report/... -update; \
	else echo "golden: no renderers yet (they arrive in M1)"; fi

## cross: compile check for macOS and Windows (INITIAL.md §4.15)
cross:
	@for t in $(CROSS_TARGETS); do \
		echo "go build ./... for $$t"; \
		GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build -o /dev/null ./...; \
	done

clean:
	rm -rf bin dist spikes/out
