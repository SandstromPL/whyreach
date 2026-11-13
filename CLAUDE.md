# CLAUDE.md — NetDoctor

NetDoctor is a single Go binary that runs **read-only** network diagnosis for Linux and Docker. It works both as a CLI and as an MCP server. It collects evidence (Docker metadata, listening sockets, DNS as a container sees it, bounded TCP probes, routes) and reports findings from a catalog of deterministic rules (`ND001`, `ND002`, …).

**Who it's for:** backend developers whose Docker runs on Linux and who run multi-service Compose stacks with an AI coding agent. Docker Desktop users on Windows and macOS come later. Details: `INITIAL.md` §2.1 and §3.7.

**Status:** M0 is done.
- The repo is scaffolded, with the module path `github.com/SandstromPL/netdoctor`.
- Throwaway spikes are in `spikes/`, and their results are in `docs/adr/0001-execution-contexts.md`.
- Next is M1, the vertical slice (`INITIAL.md` §2.3).

**Source of truth:** `INITIAL.md` holds the current design: decisions, HLD, LLD, the rule catalog and the milestones. The original project proposal (not published) is background only.
- If the two disagree, `INITIAL.md` wins.
- If code and `INITIAL.md` disagree, fix one of them in the same change.

## Environment

- Ubuntu 24.04.5, kernel 7.0, Go 1.27.0, Docker Engine 29.9.3 (API 1.56), Compose v5.7.0.
- The user is in the `docker` group. Root is available only through `sudo`; ask before using it.
- `golangci-lint` v2.15.0 is installed (via `go install`). `goreleaser` isn't installed yet (it's needed in M4).

## Commands

These are the Makefile targets; keep this list in sync with the Makefile. Until M1 adds lab scenarios and renderers, `lab`, `lab-root` and `golden` only print a notice.

```bash
make build      # CGO_ENABLED=0 go build -o bin/netdoctor ./cmd/netdoctor
make test       # go test ./...  (unit + rule fixtures; no Docker, no root, no network)
make lint       # golangci-lint run
make lab        # go test -tags lab ./test/e2e/...  (needs Docker)
make lab-root   # sudo -E go test -tags lab,privileged ./test/e2e/...  (netns executor)
make golden     # go test ./internal/report/... -update
make cross      # compile check: GOOS=darwin and GOOS=windows (amd64, arm64) go build ./...
```

Run a single test: `go test ./internal/rules -run TestND002 -v`

## Architecture (details: INITIAL.md §3–4)

```
cli / mcpserver → policy → engine → { rules, collect/host, collect/docker, executor → probe } → evidence → report
```

- **`cli`, `mcpserver`:** thin adapters with no diagnostic logic.
- **`engine`:** a staged pipeline: resolve → collect → probe → evaluate → compose. It is the only package that orchestrates I/O.
- **`rules`:** pure functions over `evidence.View`. No I/O, no `time.Now()`, no randomness.
- **`executor`:** runs probes *inside a context*. The options are `host`, `probecontainer` (the default for containers) and `netns` (only when running as root). **Never `docker exec`.**
- **`collect/docker`:** a hand-written client over the unix socket, restricted to an allowlist of method + path pattern. Probe-container lifecycle calls go through a separately constructed client with its own allowlist. There is no Docker SDK.
- **Import direction:** core packages never import `cli` or `mcpserver`, and `rules` imports only `evidence`.

## Platforms (details: INITIAL.md §3.7, §4.15)

- v0.1 supports Linux with Docker Engine only. Don't claim support for another OS or runtime until its lab run passes.
- Linux-only code (netlink, `/proc`, `setns`) carries `//go:build linux` and has an `_other.go` stub that returns `Status: unsupported`. Everything else must compile for darwin and windows; `make cross` checks this.
- Container-side checks go through the Executor. Never assume the host shares a kernel or network namespace with the containers. On Docker Desktop (macOS, Windows, Linux, and its WSL2 integration) it doesn't, and inside WSL2 the "host" is the WSL2 VM, not Windows.
- The netns executor runs only on `linux-engine` and `wsl2-engine`, and verifies that the PID belongs to the target container before calling `setns`.
- Endpoint discovery reads only endpoint fields from Docker's config, never the credential entries.
- Rules whose meaning depends on the platform read it from the evidence view. Example: ND011 never fires on Docker Desktop, where `host.docker.internal` works by default.

## Non-negotiables (safety)

1. **No shell.** Never `exec.Command("sh", "-c", …)`, and never shell out to `ip`, `ss`, `dig` or similar in product code. Use netlink, `/proc`, the Docker API and Go dialers. Tests and lab scripts may use the CLI tools.
2. **Read-only.**
   - Never change routes, firewall rules, interfaces, DNS, containers, networks, or files outside NetDoctor's own config, state and data directories. Those are the XDG directories on Linux and the platform's standard user directories on macOS and Windows (`INITIAL.md` §4.15).
   - The one allowed Docker write is the tier-2b probe container. It is gated by config, hardened, labeled `io.netdoctor.probe=1`, and reported in `side_effects`.
3. **Tool arguments can narrow permissions, never widen them.** Permission tiers come from the user's config or from MCP elicitation, never from an argument the agent supplies.
4. **Probe policy.**
   - One host:port per call. Reject CIDRs, ranges, lists and wildcards.
   - Block link-local and cloud-metadata addresses.
   - Rate-limit probes.
   - Connect, then close; never send a payload.
5. **stdout belongs to MCP in `mcp serve`.** Log with `log/slog` to stderr only. A stray `fmt.Print` breaks the protocol.
6. **Collect no secrets.**
   - Evidence never includes env var values, or file contents other than `resolv.conf` and `hosts`. ND018 (v0.3) reads env var *keys* only.
   - The one exception is NetDoctor's own setup: its config file, the `XDG_*` directory variables, `DOCKER_HOST`, and the current Docker context's endpoint (`currentContext` from `~/.docker/config.json`, plus that context's `meta.json`).
   - Never read, log or store the `auths`, `credsStore` or `credHelpers` entries of `~/.docker/config.json`.
7. **Every check has a timeout and returns an explicit `Status`.** Missing evidence is a `Gap`, never a negative result.
8. **No telemetry, no update checks.** No outbound traffic except the probes the user asked for.

## Diagnostic correctness

- Keep facts (what was observed, with evidence IDs) separate from findings (hypotheses with a confidence level). Every finding cites the evidence IDs that support it.
- A rule fires only when the evidence in its `Requires()` is present. If evidence is missing, record a gap that says how to enable the check.
- Confidence is a rule-defined label (`high`, `medium` or `low`), not a number. Contradicting evidence lowers it by one level.
- Every address in output names its context, e.g. "127.0.0.1 in api". `localhost` means something different in each container.
- Refused, timeout and unreachable are different results. Keep the errno.
- Output is deterministic. Sort everything, and never let map iteration order reach a result.
- Rule IDs (`NDxxx`) are permanent. Never renumber or reuse them.
- Listener-based rules ignore Docker's embedded-DNS listeners on `127.0.0.11` (ADR 0001).
- `Unmap()` every address that comes from Go's resolver: `/etc/hosts` entries come back as `::ffff:a.b.c.d`.

## Adding a rule (checklist)

1. Implement `Rule` in `internal/rules/ndxxx_<slug>.go`. Declare `Supersedes()` if the rule makes another one redundant.
2. Add fixtures in `internal/rules/testdata/NDxxx/`: at least one case where the rule fires and one where it must **not** fire. If the rule's meaning depends on the platform, add a must-not-fire fixture for each platform where it doesn't apply.
3. Add a lab scenario in `test/lab/ndxxx-<slug>/`, with `compose.yaml` and `scenario.yaml`.
4. Write the doc page `docs/rules/NDxxx.md`: the pitfall, the evidence, the fix, and notes on false positives.
5. Update the catalog table in `INITIAL.md` §4.6.

## MCP tools

The default answer to adding a tool is no. The surface stays at 4 tools: `diagnose_connection`, `inspect_environment`, `run_probe` and `save_report`. If a change is really needed:
- Use typed In/Out structs through `mcp.AddTool`.
- Keep annotations honest: `readOnlyHint` must be false when tier 2b is enabled.
- Return tool errors as results with `isError: true`.
- Claude Code shows the model the `structuredContent`, not the text (ADR 0001). Keep the structured output compact (about 1.5k tokens) and lead it with the verdict and summary. Also keep a text summary of similar size for other clients, and cover both with golden tests.
- Name and describe tools with the words agents search for: network, connect, docker, diagnose.

## Go conventions

- **Build:** Go 1.27 modules, `CGO_ENABLED=0`. The binary must be static because the probe container runs it on `scratch`.
- **Context:** `context.Context` is the first parameter of anything that does I/O, and cancellation is honored.
- **Errors:** wrap with `%w` and check with `errors.Is`/`errors.As`. Never turn an errno into a plain string.
- **Structure:** no global mutable state and no `init()` side effects. Constructors take their dependencies, with interfaces at package boundaries.
- **Tests:** table-driven, with `go-cmp` for diffs. Golden files live in `testdata/` and are refreshed with `-update`.
- **Dependencies:** add them deliberately. Allowed:
  - `github.com/modelcontextprotocol/go-sdk`
  - `github.com/vishvananda/netlink`, `github.com/vishvananda/netns`
  - `github.com/miekg/dns`
  - `github.com/spf13/cobra`
  - `golang.org/x/sys`
  - `github.com/google/go-cmp`
  - `github.com/BurntSushi/toml`
  - `github.com/Microsoft/go-winio` (Windows named pipe; only once native Windows support lands in v0.3)

  Anything else needs a one-line justification in the commit message.

## Out of scope until INITIAL.md says otherwise

- Kubernetes, eBPF, packet capture, parsing firewall rules, TLS/HTTP checks
- Podman, rootless Docker, Docker Desktop, macOS/Windows hosts (roadmap: `INITIAL.md` §3.7; keep the code portable anyway)
- Remediation, telemetry, SaaS, LLM calls inside NetDoctor
- C++ or Python services, plugin frameworks, a generic DAG/workflow engine

## Working agreements

- Before starting a milestone, re-read `INITIAL.md` §2, §4 and the relevant ADR in `docs/adr/`.
- Build the smallest thing that makes the milestone's lab scenario pass. Don't build ahead.
- When a design decision changes, update `INITIAL.md` or add an ADR in the same change.
- Only touch Docker resources that NetDoctor's own lab, spikes or probes created: those named `netdoctor-lab-*` or `netdoctor-spike-*`, or labeled `io.netdoctor.probe=1` or `io.netdoctor.spike=1`. Clean up with `docker compose -p <project> down -v`. Never prune or remove anything else on this machine.
