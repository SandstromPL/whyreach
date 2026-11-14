# CLAUDE.md — whyreach

whyreach is a single Go binary that runs **read-only** network diagnosis for Linux and Docker. It works both as a CLI and as an MCP server. It collects evidence (Docker metadata, listening sockets, DNS as a container sees it, bounded TCP probes, routes) and reports findings from a catalog of deterministic rules (`WR001`, `WR002`, …).

**Who it's for:** backend developers whose Docker runs on Linux and who run multi-service Compose stacks with an AI coding agent. Docker Desktop users on Windows and macOS come later. Details: `INITIAL.md` §2.1 and §3.7.

**Status:** M0 to M5 are done.
- M0: the repo is scaffolded (module path `github.com/SandstromPL/whyreach`); throwaway spikes are in `spikes/`, with results in `docs/adr/0001-execution-contexts.md`; the rule experiments (`spikes/experiments.sh`, results in `docs/research/rule-experiments.md`) decided the rule order in `docs/adr/0002-rule-order.md`.
- M1, the vertical slice (`INITIAL.md` §2.3): the CLI `whyreach [--from SOURCE] HOST:PORT` diagnoses with WR008, WR007, WR004 and WR002.
- M2: all 14 v0.1 rules; host↔container flows; `policy` (tiers, probe allowlist, rate limit, audit log); the MCP server (`whyreach mcp serve`, four tools, consent for probe containers: `docs/adr/0003-mcp-server.md`); `inspect`, `probe` and `doctor`. `make lab` passes 20 scenarios with probe containers on and off, and `make lab-agent` has a headless agent diagnose each one through the MCP tools alone.
- M3: the netns executor. As root on Linux Docker Engine, container checks enter the containers' network namespaces with `setns`, with no Docker write; a probe container stands in only when entering fails and tier 2b is on (ADR 0001, M3 amendment). `make lab-root` passes all 20 scenarios through it.
- M4: through MCP, outside names are looked up only with the user's approval or under `[probe] names`, and nameservers pass the block list (§10 Q11, ADR 0003's amendments); `save_report` always redacts (Q12); `diagnose --report`, `report list|show|export` and `rules list|explain`; the demo (`demo/compose.yaml`, WR007); release builds prepared but never published (`.goreleaser.yaml`, `Dockerfile`, `.github/workflows/release.yml`, `server.json`). A fresh agent installed whyreach from a release-layout archive, connected it and diagnosed the demo with only the docs.
- Before v0.1.0 is tagged (2026-11-14), `INITIAL.md` §10 Q13–Q15 are built:
  - a blocked nameserver that is one of the host's own resolvers is asked, for DNS only;
  - each approval of a name or an address covers 3 uses;
  - through MCP, a private address outside Docker's networks and the host's own addresses needs the user's approval of that address and port.
- M5: the agent benchmark (`INITIAL.md` §6.4, `make lab-bench`). For each lab scenario, one headless agent gets a shell and another gets whyreach's four tools. The shell agent is contained by bwrap, a read-only Docker proxy and a guard hook. Both agents were right on all 21 scenarios. whyreach's was clearly better on 18 (fewer calls, tokens, time and cost, and no unsafe command), so §6.4 passes. Method and results: `docs/research/agent-benchmark.md`. Launch drafts: `docs/launch/`.
- Next is publishing and the launch, which are the owner's steps (tag, release, image, MCP Registry, the README results section and the launch post).

**Source of truth:** `INITIAL.md` holds the current design: decisions, HLD, LLD, the rule catalog and the milestones. The original project proposal (not published) is background only.
- If the two disagree, `INITIAL.md` wins.
- If code and `INITIAL.md` disagree, fix one of them in the same change.

## Environment

- Ubuntu 24.04.5, kernel 7.0, Docker Engine 29.9.3 (API 1.56), Compose v5.7.1.
- Go: the system install (`/usr/local/go`, root-owned) is 1.27.0, but `go.mod` pins `toolchain go1.27.4`. The go command downloads and uses that toolchain automatically (`GOTOOLCHAIN=auto`), and CI's `setup-go` reads the same directive. When `make vuln` reports a standard-library vulnerability, bump the `toolchain` line to the patch release that fixes it.
- The user is in the `docker` group. Root is available only through `sudo`; ask before using it.
- `golangci-lint` v2.15.0 is installed (via `go install`). goreleaser isn't installed: the Makefile pins it (`GORELEASER`, v2.19.0) and runs it with `go run`, like govulncheck.

## Commands

These are the Makefile targets; keep this list in sync with the Makefile.

```bash
make build      # CGO_ENABLED=0 go build -o bin/whyreach ./cmd/whyreach
make test       # go test ./...  (unit + rule fixtures; no Docker, no root, no network)
make lint       # golangci-lint run
make vuln       # govulncheck ./...  (pinned version; known CVEs in code we call, stdlib included; needs network)
make lab        # go test -tags lab -count=1 ./test/e2e/...  (needs Docker; scenarios in test/lab/)
make lab-agent  # go test -tags lab,agent -count=1 -run TestAgent ./test/e2e/...  (Docker + claude CLI; a small model diagnoses each scenario over MCP)
make lab-bench  # go test -tags lab,agent,bench -count=1 -run TestBench ./test/e2e/...  (the M5 agent benchmark: a shell-only agent, sandboxed, against a whyreach-only one on every scenario; Docker, bwrap, claude CLI; masked results in bin/bench/)
make lab-root   # builds as you, then sudo runs only the test binaries: the executor's root-only test and TestLabNetns (tags lab,privileged: every scenario through the netns executor, no Docker writes)
make golden     # go test ./internal/report/... ./internal/mcpserver/... -update  (text, the compact MCP structured form, Diagnosis JSON, the MCP tools)
make cross      # compile check: GOOS=darwin and GOOS=windows (amd64, arm64) go build ./...
make release-check     # goreleaser check (pinned, go run; downloads it)
make release-snapshot  # goreleaser release --snapshot --skip=docker: archives and checksums.txt in dist/, nothing published
make release           # the release workflow's step on a v* tag; it publishes, so it refuses to run outside GitHub Actions
make clean      # rm -rf bin dist spikes/out
```

Run a single rule's fixtures: `go test ./internal/rules -run 'TestFixtures/WR002' -v`. Run one lab scenario: `go test -tags lab -count=1 ./test/e2e -run 'TestLab/wr002' -v`.

## Architecture (details: INITIAL.md §3–4)

```
cli / mcpserver → policy → engine → { rules, collect/host, collect/docker, executor → probe } → evidence → report
```

- **`cli`, `mcpserver`:** thin adapters with no diagnostic logic. They reach the engine only through `policy`; `main` wires the MCP server into the CLI's `mcp serve`.
- **`policy`:** validates arguments, decides the permission tiers (config, or the user's consent through MCP elicitation), guards the executors (probe allowlist at dial time, rate limit) and writes the audit log. It is the only package that builds an engine.
- **`config`:** the XDG config file. Permission tiers come only from here, or from the user's approval of an MCP elicitation, which lasts the session.
- **`engine`:** a staged pipeline: resolve → collect → probe → evaluate → compose (plus the host's side after the probes, when only the lookup shows the target is the host). It is the only package that orchestrates I/O.
- **`rules`:** pure functions over `evidence.View`. No I/O, no `time.Now()`, no randomness.
- **`executor`:** runs probes *inside a context*. The options are `host`, `probecontainer` (the default for containers) and `netns` (only when running as root). **Never `docker exec`.**
- **`collect/docker`:** a hand-written client over the unix socket, restricted to an allowlist of method + path pattern. Probe-container lifecycle calls go through a separately constructed client with its own allowlist. There is no Docker SDK.
- **Import direction:** nothing but `main` imports `cli` or `mcpserver`, `rules` imports only `evidence`, and only `policy` calls `engine.New`. `cmd/whyreach/imports_test.go` enforces it.
- **`report`:** the text rendering, the compact structured form MCP clients read (cut to 6000 bytes of JSON), and report bundles with redaction.

## Platforms (details: INITIAL.md §3.7, §4.15)

- v0.1 supports Linux with Docker Engine only. Don't claim support for another OS or runtime until its lab run passes.
- Linux-only code (netlink, `/proc`, `setns`) carries `//go:build linux` and has an `_other.go` stub that returns `Status: unsupported`. Everything else must compile for darwin and windows; `make cross` checks this.
- Container-side checks go through the Executor. Never assume the host shares a kernel or network namespace with the containers. On Docker Desktop (macOS, Windows, Linux, and its WSL2 integration) it doesn't, and inside WSL2 the "host" is the WSL2 VM, not Windows.
- The netns executor runs only on `linux-engine` and `wsl2-engine`, and verifies that the PID belongs to the target container before calling `setns`.
- Endpoint discovery reads only endpoint fields from Docker's config, never the credential entries.
- Rules whose meaning depends on the platform read it from the evidence view. Example: WR011 never fires on Docker Desktop, where `host.docker.internal` works by default.
- In a container (the image, `INITIAL.md` §3.5), whyreach's own network namespace is the host's only with `--network host`, and Docker's PIDs are its own only with `--pid host`. It asks Docker about its own container (found from the files Docker mounts over `/etc`); only without Docker's answer does a Docker bridge in sight decide the network. Without them, host-side checks and containers' listeners are unsupported records with the advice, never the container's own state passed off as the host's.

## Non-negotiables (safety)

1. **No shell.** Never `exec.Command("sh", "-c", …)`, and never shell out to `ip`, `ss`, `dig` or similar in product code. Use netlink, `/proc`, the Docker API and Go dialers. Tests and lab scripts may use the CLI tools.
2. **Read-only.**
   - Never change routes, firewall rules, interfaces, DNS, containers, networks, or files outside whyreach's own config, state and data directories. Those are the XDG directories on Linux and the platform's standard user directories on macOS and Windows (`INITIAL.md` §4.15).
   - The only allowed Docker writes are tier 2b's: importing the probe image (`whyreach-probe:<version>-<digest>`, once per build) and running the probe container. Both are gated by config, labeled `io.whyreach.probe=1`, and reported in `side_effects`. The container is also hardened, and whyreach removes it itself after reading its logs: no AutoRemove, which would delete the output first (ADR 0001, amendment).
3. **Tool arguments can narrow permissions, never widen them.** Permission tiers come from the user's config or from MCP elicitation, never from an argument the agent supplies.
4. **Probe policy.**
   - One host:port per call. Reject CIDRs, ranges, lists and wildcards.
   - Block link-local and cloud-metadata addresses, as targets and as nameservers. The one exception: a nameserver that is one of the host's own resolvers (in the host's `/etc/resolv.conf` or systemd-resolved's `/run/systemd/resolve/resolv.conf`) may be asked, for DNS on port 53 only; a connect to it stays blocked, and one that only a container's `resolv.conf` names stays refused (`INITIAL.md` §10 Q13).
   - Rate-limit probes.
   - Connect, then close; never send a payload.
   - Through MCP, never send a lookup of an outside name (one with a dot, other than `localhost`, `*.localhost`, `host.docker.internal` and `gateway.docker.internal`) unless Docker's metadata or the source's hosts file knows it, the user approved that exact name through elicitation, or `[probe] names` covers it. An approval covers 3 lookups in the session (`probe.ApprovalBudget`); then whyreach asks again. The probe enforces this at send time (`probe.Limits`). The CLI is unrestricted (`INITIAL.md` §10 Q11, Q14).
   - Through MCP, never connect to a private address that only the allowlist's `rfc1918` class admits unless the user approved that exact address and port through elicitation (3 connects an approval) or an explicit address or CIDR in `[probe] allow` covers it. Loopback, Docker's bridge networks (on macvlan and ipvlan, only the containers' own addresses), and the host's own interface addresses stay free. The guard checks literal targets and the probe checks every resolved address at dial time, counting the batch's approved connects down. The CLI is unrestricted (`INITIAL.md` §10 Q15).
5. **stdout belongs to MCP in `mcp serve`.** Log with `log/slog` to stderr only. A stray `fmt.Print` breaks the protocol.
6. **Collect no secrets.**
   - Evidence never includes env var values, or file contents other than `resolv.conf` and `hosts`. WR018 (v0.3) reads env var *keys* only.
   - The one exception is whyreach's own setup: its config file, the `XDG_*` directory variables, `DOCKER_HOST`, and the current Docker context's endpoint (`currentContext` from `~/.docker/config.json`, plus that context's `meta.json`).
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
- Rule IDs (`WRxxx`) are permanent. Never renumber or reuse them.
- Listener-based rules ignore Docker's embedded-DNS listeners on `127.0.0.11` (ADR 0001).
- Every rule has a layer (`INITIAL.md` §4.5, ADR 0002). The primary finding comes from the earliest broken layer. Consequences of it are suppressed through `Supersedes()`, and independent findings are kept as "also found".
- Decide "name not found" (WR005) from Docker metadata, never from the DNS rcode. Unknown names come back SERVFAIL or NXDOMAIN depending on the host's resolver.
- "Refused" alone proves nothing: at least nine rules produce it (`docs/research/rule-experiments.md`). Listeners and metadata decide which one applies.
- `Unmap()` every address that comes from Go's resolver: `/etc/hosts` entries come back as `::ffff:a.b.c.d`.

## Adding a rule (checklist)

1. Implement `Rule` in `internal/rules/wrxxx_<slug>.go`. Give it a `Layer()` from the precedence table, and declare `Supersedes()` if it makes another rule redundant.
2. Add fixtures in `internal/rules/testdata/WRxxx/`: at least one case where the rule fires and one where it must **not** fire. If the rule's meaning depends on the platform, add a must-not-fire fixture for each platform where it doesn't apply.
3. Add a lab scenario in `test/lab/wrxxx-<slug>/`, with `compose.yaml` and `scenario.yaml` (format: `INITIAL.md` §5 and `test/e2e/lab_test.go`), and expectations both with probe containers on and with the default config.
4. Write the doc page `docs/rules/WRxxx.md`: the pitfall, the evidence, the fix, and notes on false positives.
5. Update the catalog table in `INITIAL.md` §4.6.

## MCP tools

The default answer to adding a tool is no. The surface stays at 4 tools: `diagnose_connection`, `inspect_environment`, `run_probe` and `save_report`. If a change is really needed:
- Use typed In/Out structs through `mcp.AddTool`.
- Keep annotations honest: `readOnlyHint` must be false when tier 2b is enabled.
- Return tool errors as results with `isError: true`.
- Probe containers by consent: ask the user once per session, only when they'd change the answer, through the client's elicitation (both protocol paths; ADR 0003). Never let an argument answer it.
- Outside names and private addresses by consent too, per name or address and port: an approval covers that exact one for 3 uses, a declined one isn't asked about again, and questions about names and addresses share the session's limit of 3. The request state says which question an answer belongs to (ADR 0003's M4 and 2026-11-14 amendments).
- No argument relaxes a privacy default: `save_report` always redacts; an unredacted bundle comes only from the CLI (`INITIAL.md` §10 Q12). `internal/mcpserver/testdata/tools.golden` pins the tools' schemas.
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
  - `golang.org/x/sync` (`errgroup`, for the engine's collect stage)
  - `github.com/google/go-cmp`
  - `github.com/BurntSushi/toml`
  - `go.yaml.in/yaml/v3` (the lab harness only: it parses `scenario.yaml`)
  - `github.com/Microsoft/go-winio` (Windows named pipe; only once native Windows support lands in v0.3)
  - `golang.org/x/net` (`route` for routing sockets; only once native macOS support lands in v0.3)

  Anything else needs a one-line justification in the commit message.

## Out of scope until INITIAL.md says otherwise

- Kubernetes, eBPF, packet capture, parsing firewall rules, TLS/HTTP checks
- Podman, rootless Docker, Docker Desktop, macOS/Windows hosts (roadmap: `INITIAL.md` §3.7; keep the code portable anyway)
- Remediation, telemetry, SaaS, LLM calls inside whyreach
- C++ or Python services, plugin frameworks, a generic DAG/workflow engine

## Working agreements

- **Commit every change as you go, without asking.** This is the project owner's standing instruction.
  - Make small commits with descriptive messages, after the relevant checks pass.
  - Work on a task branch, and fast-forward `main` when the task is done.
  - Never push unless asked.
- Before starting a milestone, re-read `INITIAL.md` §2, §4 and the relevant ADR in `docs/adr/`.
- Build the smallest thing that makes the milestone's lab scenario pass. Don't build ahead.
- When a design decision changes, update `INITIAL.md` or add an ADR in the same change.
- Only touch Docker resources that whyreach's own lab, spikes or probes created: those named `whyreach-lab-*`, `whyreach-spike-*` or `whyreach-exp-*`, or labeled `io.whyreach.probe=1` or `io.whyreach.spike=1`. Clean up with `docker compose -p <project> down -v`. Never prune or remove anything else on this machine.
