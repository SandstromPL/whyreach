# whyreach — INITIAL.md

> **What this is:** the build brief for whyreach's first release: the decisions that came out of the critique, the HLD, the LLD, MVP scope, and the test plan.
> Where this file and the original project proposal (not published) disagree, this file wins. The proposal stays as background and rationale.
> **Name:** the project was renamed from NetDoctor to **whyreach** on 2026-11-13 because of a trademark conflict (§10 Q5). The original proposal keeps the old name.
>
> **Status:** M0 done (scaffold, spikes, ADR 0001); next is M1 · **Updated:** 2026-11-13
> **Dev box:** Ubuntu 24.04.5, kernel 7.0, Go 1.27.0 (builds use the `toolchain go1.27.4` pinned in `go.mod`), Docker Engine 29.9.3 (API 1.56), Compose v5.7.0

---

## 0. TL;DR

- **What we build:** a single Go binary that diagnoses network connectivity between containers and between containers and the host. It is read-only and works both as a CLI and as an MCP server.
- **Who it's for:** backend developers whose Docker runs on Linux (on their own machine, a remote dev box or a remote devcontainer, and in CI from v0.2), who run multi-service Compose stacks and use an AI coding agent (§2.1). Docker Desktop users on Windows and macOS come next (§3.7).
- **Where it has an edge:** a tested catalog of the Docker networking mistakes developers actually make (`WR001`, `WR002`, …). Each one is detected by a deterministic rule that correlates several pieces of evidence. whyreach is not a wrapper around `ping` or `ss`.
- **The key design decision:** checks that must run inside a container go through a pluggable **Executor**. The default executor starts a short-lived, hardened *probe container* that shares the target container's network namespace. This needs only the Docker API. The result is no root requirement and support for distroless images. Later, the same path covers Docker Desktop on macOS and Windows without a rewrite.
- **How we prove it:** a failure lab with one Compose scenario per rule, plus a benchmark that compares an agent using plain bash against an agent using only whyreach (§6.4).

---

## 1. Critique → decisions

Each row is a weakness in the original proposal and the decision that replaces it.

| # | Weakness in the proposal | Decision |
|---|---|---|
| D1 | It names linux-mcp-server as the main competitor. The real competitor is a coding agent (Claude Code, Codex) running `docker inspect`, `docker exec` and `ss` through its shell. Docker's own Gordon (`docker ai`) also competes, though it requires Docker Desktop and a Docker account. | whyreach has to win where shell loses: distroless containers (no `ss`, `curl` or `nslookup` inside), DNS seen from the container's own resolver (`127.0.0.11`), correlation across layers, and one tool call where the shell needs about ten. The benchmark in §6.4 must show this before v1.0. |
| D2 | The failure catalog is textbook (refused vs. timeout), not what developers actually run into. | Build the catalog from real pitfalls (§4.6): `localhost` used inside a container, an app bound to 127.0.0.1, the published port used instead of the container port, separate Compose networks, `host.docker.internal` on Linux, startup races, Docker subnets overlapping a VPN or LAN, IPv6 `localhost`. **The catalog is the product.** |
| D3 | "Run checks from the container's namespace, where supported" hides the hardest problem in the project. | Define an explicit `Executor` abstraction with three strategies (§3.3). Settle the choice in M0 with spikes, not halfway through implementation. |
| D4 | It promises least privilege, but Docker socket access is effectively root, `setns` needs `CAP_SYS_ADMIN`, and reading nftables needs `CAP_NET_ADMIN`. | Say plainly in the docs that the read-only guarantee comes from whyreach's code (a Docker client that only allows listed endpoints, and no shell), not from OS privileges. Detect capabilities at runtime and report what could not be checked. Recommend `docker-socket-proxy` for users who want OS-level enforcement. |
| D5 | Linux-only conflicts with the stated target user. Probably most Compose users run Docker Desktop on macOS or Windows, where container PIDs and network namespaces live inside a VM. Docker Desktop for Linux uses a VM too. | Make the Docker-API-only path (the probe container) the default for container checks, and keep Linux-only code behind build tags from day one. Windows via WSL2 follows in v0.2 and native macOS/Windows builds in v0.3; `docker run … whyreach` gives a zero-install option. Host-level checks stay Linux-only unless users ask (§3.7). |
| D6 | 13 fine-grained MCP tools. Every tool schema costs context tokens on every turn, and agents choose worse among many similar tools. | Expose 4 tools (§4.10). The engine runs the workflows; the low-level primitives are escape hatches. |
| D7 | It never decides whether the LLM or the engine runs the investigation. | The engine runs it, deterministically and with tests. The agent works out what to diagnose (from where to where), reads the diagnosis, and follows the machine-readable `next_checks`. whyreach never calls an LLM itself. |
| D8 | Demand validation is only 5–10 interviews. | Also collect the top ~20 failure signatures from StackOverflow, the Docker forums and GitHub issues. That list becomes both the rule backlog and the lab. |
| D9 | Probes can be abused: a prompt-injected agent could scan the LAN or reach the cloud metadata service. | Policy (§4.9): one host:port per call, no CIDRs or ranges, block link-local and metadata addresses, rate limits, and an audit log. **Tool arguments can narrow permissions but never widen them.** |
| D10 | The 8–10 week estimate. | Plausible for the MVP full-time. Part-time, plan for about twice that. The failure lab takes longest, so start it in week 1. |

---

## 2. FEATURE — what we build first

### 2.1 Target users

**Primary persona (v0.1):** a backend developer whose Docker runs on Linux, who runs a multi-service stack (API, database, worker) with Docker Compose, and who uses an AI coding agent (Claude Code, Codex, Cursor, …).
- **Trigger:** one service suddenly can't reach another (`ECONNREFUSED`, `getaddrinfo ENOTFOUND`, a timeout), and they can't tell which layer is broken.
- **Job to be done:** "Tell me why A can't reach B, with proof, in one step, without changing anything."
- The project's own author fits this persona (Ubuntu, Docker Engine, Claude Code). Dogfood every milestone.

| Segment | Where Docker runs | Served from | Notes |
|---|---|---|---|
| Linux laptop and desktop developers | local Docker Engine | v0.1 | smallest segment; most willing to try a new Go CLI; easiest to reach |
| Remote and cloud dev environments: GitHub Codespaces, remote devcontainers, cloud VMs, SSH dev boxes | a Linux machine or VM | v0.1 | includes many Mac users whose Docker actually runs on remote Linux, as long as whyreach and the agent run on that machine (Remote-SSH, Codespaces). A macOS binary that talks to a remote daemon through `DOCKER_HOST` or `docker context` comes in v0.3 (§3.7) |
| CI pipelines with Compose-based integration tests | Linux runners | v0.2 (CI mode) | run `whyreach diagnose --from <source> <target> --json` when tests fail; also useful to AI agents that fix CI |
| Docker Desktop users on Windows and macOS | a Linux VM managed by Docker Desktop | v0.2 (Windows via WSL2), v0.3 (native builds) | likely the biggest segment. In the 2025 Stack Overflow survey (professional use, multi-select), Windows was at 49.5% and macOS at 32.9%, against 27.7% for Ubuntu, the top Linux distro. The survey doesn't measure Docker Desktop itself. See §3.7 |

**Indirect beneficiaries:**
- Open-source maintainers: they can ask people who report "can't connect to the database" to attach a report bundle from `whyreach diagnose … --report` (exported with `whyreach report export <id>`), the way `flutter doctor` output is used.
- Platform teams: redacted report bundles help them triage "works on my machine" tickets.

**Not target users:** network engineers managing routers and switches, people running Kubernetes in production (Hubble, k8sgpt and `kubectl debug` serve them), and anyone who wants a network scanner. Feature requests from these groups are out of scope by default.

**What this means for the design:**
- The users are developers, not network specialists, so findings speak in application terms (bind address, service name, port) rather than packet terms.
- They already have an AI agent, so MCP is a first-class interface, and the CLI is its equal.
- They think in Compose services, so Compose project and service names are resolved first-class (§4.3).

### 2.2 MVP scope (v0.1)

**In scope:**
- `diagnose_connection` for these directions:
  - container → container, with the destination given as a container name, Compose service, alias or IP
  - container → host
  - host → container, through published ports
  - host → a service on the same host
- Evidence collected:
  - Docker metadata: containers, networks, ports, Compose labels, health
  - the destination's listening sockets, read from inside its network namespace
  - DNS as the source container sees it
  - a bounded TCP connect from the source's context
  - host interfaces and routes, via netlink
- The 14 rules marked v0.1 in §4.6 (WR001–WR012, WR019, WR020), built in the order set by ADR 0002.
- A CLI (`whyreach diagnose …`) and an MCP stdio server, both running the same engine.
- Text and JSON output, plus a Markdown report bundle with redaction.
- A failure lab with at least one scenario per MVP rule. CI runs it.

**Out of scope for v0.1:** Kubernetes, eBPF, packet capture, parsing firewall rules, TLS and HTTP checks, Podman, rootless Docker, Docker Desktop, macOS and Windows hosts, remediation, telemetry, and any LLM call. The platform roadmap is in §3.7.

### 2.3 First vertical slice (exit criterion for M1)

Scenario: `worker` cannot reach `api`. Following ADR 0002, the three injected variants are the two most frequent real-world failures plus the classic bind bug. Each must produce the correct primary finding:

1. `worker` is configured with `localhost:8080` → **WR007** (high), with the fix `api:8080`.
2. `api` and `worker` are in different Compose projects → **WR004** (high). The timeout seen when connecting by IP must not surface as WR016.
3. `api` listens on `127.0.0.1:8080` → **WR002** (high).

There is also a control scenario where everything works. It must return the verdict `no_problem_reproduced`. Experiments E1 and E2 in `spikes/experiments/` are the starting point for these lab scenarios.

---

## 3. HLD

### 3.1 Context and trust boundaries

```
Developer ─► MCP client (Claude Code, Codex, Cursor, …)
                 │ stdio JSON-RPC          ◄─ UNTRUSTED: tool args may be prompt-injected
                 ▼
   ┌──────────────────────────────┐
   │ whyreach (one Go binary)    │        ◄─ TRUSTED CODE that holds
   │ cli · mcpserver · policy     │           root-equivalent Docker access
   │ engine · rules · executors   │
   └───────┬──────────────┬───────┘
           │ netlink,     │ Docker Engine API (unix socket)
           │ /proc/net    │ endpoint allowlist; writes only for opt-in probe containers
           ▼              ▼
      Linux kernel      dockerd ─► containers, networks
```

### 3.2 Components

```
 cli ──┐                         ┌─► rules            pure: evidence → findings
       ├─► policy ─► engine ─────┼─► collect/docker   allowlisted Engine API client
 mcp ──┘                         ├─► collect/host     netlink, /proc/net
                                 └─► executor ─► probe (dns, tcp, listeners)
                                       ├ host
                                       ├ probe-container   (default for containers)
                                       └ netns             (when running as root)

 engine ─► evidence store ─► report   (text · JSON · Markdown bundle · redaction)
```

| Component | Owns | Must not |
|---|---|---|
| `cli`, `mcpserver` | argument parsing, rendering, transport | contain diagnostic logic |
| `policy` | validation, permission tiers, probe-target policy, rate limits, audit log | be bypassable through tool arguments |
| `engine` | one workflow per question type, deadlines, partial results | parse raw kernel or Docker output |
| `collect/host` | netlink (links, addresses, routes, neighbours), host listeners | know anything about rules |
| `collect/docker` | a typed Docker client restricted to an endpoint allowlist | call any endpoint that isn't on the allowlist |
| `executor` | running probes *inside a context* (the host's or a container's netns) | decide what a result means |
| `rules` | evidence → findings, pure and deterministic | perform any I/O |
| `report` | rendering, redaction, writing bundles | collect anything |

### 3.3 Execution contexts: the key design decision

To answer "can worker reach api:8080?", the DNS lookup and TCP connect have to happen **inside worker's network namespace**. To answer "is api listening on 0.0.0.0?", the socket table has to be read **inside api's network namespace**. There are three ways to do that:

| Strategy | How it works | Privilege needed | Works on distroless images? | Docker Desktop / remote daemon? | Docker writes | Latency |
|---|---|---|---|---|---|---|
| **probe-container** (default) | Create a tiny container with `NetworkMode: container:<target>`, run the whyreach probe in it, read its stdout, remove it | Docker API only | ✅ | ✅ (later) | imports the labeled probe image once per version; creates, starts and removes 1 labeled container | ~0.5–2 s |
| **netns** (fast path) | `setns()` into `/proc/<pid>/ns/net` on a locked OS thread | root or `CAP_SYS_ADMIN` | ✅ | ❌ (Linux Engine only) | none | ms |
| `docker exec` | Run `ss` or `nslookup` inside the target | Docker API | ❌ (the tools are missing) | ✅ | an exec | ~0.3 s |

**Decision:** implement `probe-container` first and `netns` second (selected automatically when running as root). Never use `docker exec`.

Why probe-container is the right default:
- A container started with `--network container:X` shares X's network namespace. Docker also gives it **X's own `/etc/resolv.conf` and `/etc/hosts`**, so the probe's DNS view matches the app's exactly: the embedded DNS at 127.0.0.11, `extra_hosts`, and aliases. *(Verified in M0, ADR 0001.)*
- Reading `/proc/net/tcp` and `/proc/net/tcp6` from inside the probe lists X's sockets. That checks the bind address without root and without any tools inside X.
- No registry pull is needed. On Linux, whyreach imports its own static binary as a `FROM scratch` image named `whyreach-probe:<version>`. When whyreach itself runs as a container, it reuses its own image.
- The probe is hardened: `CapDrop: ALL`, `ReadonlyRootfs`, `User: 65534`, `no-new-privileges`, no mounts, no environment, a pids limit and a memory limit, the label `io.whyreach.probe=1`, and a hard timeout.
- It does **not** use AutoRemove: the daemon deletes an auto-removed container, logs included, as soon as it exits, before whyreach can read its output (ADR 0001, amendment). whyreach removes each probe itself after reading the logs, and sweeps leftovers from a crash at startup by label.

**Trade-off:** importing the probe image and creating a container are Docker writes. Both are therefore **tier 2b** (§4.9): off unless the user enables them in config, or approves through MCP elicitation where the client supports it. Every result reports them in `side_effects` (for example: `"ephemeral probe container wr-probe-3f2a (removed)"`, plus `"imported image whyreach-probe:0.1.0"` on first use). `changes_made` stays `false`.

**Verified in M0 (ADR 0001):** the probe container works exactly as described above, hardened and without a registry pull.
- **Listeners from the host:** on Linux Docker Engine, the destination's listeners can also be read from the host through `/proc/<pid>/net/tcp{,6}`. This needs no root and no Docker write, once `/proc/<pid>/cgroup` confirms that the PID belongs to the container.
- **Without tier 2b:** v0.1 can still conclude most of its rules. The rule experiments (`docs/research/rule-experiments.md`) show that, of the v0.1 rules, only WR020 depends on the probe container. WR005 and WR011 just lose their DNS confirmation.
- **Still needs the probe container or root:** WR020, WR014 and WR016; WR021 and WR022, which weren't reproduced but are marked Probe? "yes" in §4.6; and confirming reachability from the source.

### 3.4 Main flow: `diagnose_connection(from=container:worker, to=api:8080)`

1. **Parse and guard.** Turn the arguments into typed endpoints. Policy checks the permission tier and the shape of the target.
2. **Resolve entities.** Find `worker` through Docker. Match `api` against container names, Compose services and network aliases on worker's networks.
3. **Collect (in parallel).** Inspect both containers and their networks. Read api's listening sockets from inside api's network namespace.
4. **Probe from worker's namespace.** Look up `api` (`/etc/hosts` first, then DNS for A and AAAA). Try a TCP connect to each resolved address (at most 4, 2 s each).
5. **Evaluate.** Run every rule whose required evidence exists. Rules that lack evidence become gaps.
6. **Compose.** Rank the findings, choose a verdict, and attach facts, `next_checks` and `side_effects`. Then render for MCP or the CLI.

### 3.5 Deployment modes

| Mode | How it runs | Sees the host's netns? | Container checks | Notes |
|---|---|---|---|---|
| Native (default) | `whyreach mcp serve` / `whyreach diagnose …` | ✅ | ✅ via probe-container | Linux only |
| Native as root | `sudo whyreach diagnose …` | ✅ | ✅ via the netns fast path, no Docker writes | for CLI use; avoid as an MCP server |
| As a container | `docker run --rm -i -v /var/run/docker.sock:/var/run/docker.sock <image> mcp serve` | ❌ (unless `--network host --pid host`) | ✅ | zero-install; the route to macOS and Windows (v0.3+) |
| Inside WSL2 (Windows) | the MCP client on Windows launches it with `wsl.exe -d <distro> --exec /abs/path/whyreach mcp serve` (§3.7, item 6) | describes the WSL2 VM, not Windows | ✅ via probe-container, through the socket that Docker Desktop's WSL integration provides (WSL 2 backend and Linux-containers mode only) | v0.2; the Linux build runs unchanged |

### 3.6 Non-functional requirements

- **Latency:** p50 under 3 s, and a hard deadline of 15 s per diagnosis. MCP clients time out, and partial results are better than none.
- **Output size:** about 1.5k tokens or less, both for the MCP structured content (which is what Claude Code shows the model, ADR 0001) and for the text summary other clients see. Raw evidence goes only into report bundles.
- **Network:** no outbound traffic except the probes the user asked for. No telemetry and no update checks.
- **Determinism:** the same evidence always produces byte-identical findings. Everything is sorted; map iteration order never leaks into output.
- **Degradation:**
  - Without Docker access, only host checks run.
  - Without root, the netns executor is unavailable.
  - Without probe permission, whyreach names the gap and says how to enable it.
  - Missing evidence is **never** treated as a negative result.

### 3.7 Platform support (Linux, Windows, macOS)

**Why container checks can be portable:** containers always run on a Linux kernel. On macOS and Windows, Docker Desktop (or OrbStack, or Colima) runs a hidden Linux VM. whyreach on the host can't see inside that VM (no `/proc`, no network namespaces), but the probe container runs *inside* it, next to the user's containers, and reports back through the Docker API. Host-level checks have no such shortcut: each OS needs its own code.

| Capability | Linux (Docker Engine) | Windows (Docker Desktop + WSL2) | macOS (Docker Desktop, OrbStack, Colima) |
|---|---|---|---|
| Container ↔ container | ✅ v0.1 | 🟡 v0.2 by running the Linux build inside WSL2; native `.exe` in v0.3 | 🟡 v0.3, through the probe container |
| Container → service on the host | ✅ v0.1 | 🟡 v0.2/v0.3, with Desktop-specific rules | 🟡 v0.3, with Desktop-specific rules |
| Host → container (published ports) | ✅ v0.1 | 🟡 partial: Desktop forwards published ports from the host into the VM | 🟡 partial, for the same reason |
| Host network state (routes, interfaces, listening ports, VPN overlap) | ✅ netlink + `/proc` | ⚠️ inside WSL2 this describes the WSL2 VM, not Windows; a Windows collector only on demand | ❌ needs a macOS collector; only on demand |
| Direct namespace entry (`setns`, needs root) | ✅ | ❌ the engine's PIDs mean nothing in the user's distro | ❌ the containers are inside a VM |
| Windows containers | n/a | ❌ out of scope | n/a |

Docker Engine installed directly inside a WSL2 distro (without Docker Desktop) is supported from v0.2. It behaves like the Linux column, including the netns fast path, except that host checks describe the WSL2 VM. Docker itself recommends Docker Desktop over this setup, and WSL shuts down idle distros (which stops `dockerd`), so `whyreach doctor` should report both.

**Other runtimes:**
- Docker Desktop for Linux also runs a VM, so it behaves like the macOS column: the probe container works, direct namespace entry doesn't, and host checks describe the Linux host rather than the VM. Planned for v0.3.
- OrbStack, Colima (with its default `docker` runtime), Rancher Desktop (with the moby engine) and Podman (through its Docker-compatible API) should work through the probe container. Each one must pass the lab before the docs list it as supported. Rancher Desktop in containerd/nerdctl mode and Colima with `--runtime containerd` or `incus` have no Docker API and aren't supported.
- Docker Desktop with Enhanced Container Isolation (ECI, common on business plans):
  - Docker's docs don't mention `--network container:`. Sysbox, which ECI is built on, supports sharing a network namespace between containers, so the probe container is expected to work, but it must be tested (open question 7).
  - ECI refuses `--network host` and `--pid host`, and it blocks mounting the Docker socket into a container unless an admin allowlists the image. So the "As a container" deployment mode (§3.5) won't work there by default.
  - Detect ECI (the container's `HostConfig.Runtime` is `sysbox-runc`) and say so clearly instead of failing obscurely.

**What native macOS and Windows support requires (about 1–2 weeks, container checks only):**
1. **Build tags from day one.** Linux-only code carries `//go:build linux` and has an `_other.go` stub. That covers `collect/host`, the netns executor in `executor`, the listeners probe in `probe`, and the `/proc` reads in `platform`. Every package therefore compiles for linux, darwin and windows, and the missing checks surface as `unsupported` gaps (§4.15).
2. **Embedded Linux probe binaries.** Non-Linux builds embed linux/amd64 and linux/arm64 probe binaries (`go:embed`) and import the one that matches the daemon's architecture. A macOS or Windows binary can't run inside a Linux container.
3. **Docker endpoint discovery.**
   - Order: `DOCKER_HOST` first, then the current `docker context`, then the platform default.
   - Platform defaults:
     - `/var/run/docker.sock` on Linux Engine
     - `~/.docker/desktop/docker.sock` on Docker Desktop for Linux
     - `~/.docker/run/docker.sock` on macOS, where the `/var/run/docker.sock` symlink is optional
     - the named pipe `//./pipe/docker_engine` on Windows, which needs `Microsoft/go-winio`
   - Probe the endpoint at runtime and report which one was used.
   - Read only the endpoint fields from Docker's config. Never read or store the credential entries in `~/.docker/config.json` (`auths`, `credsStore`, `credHelpers`).
4. **Platform-aware rules.** `platform` classifies the environment as one of:
   - `linux-engine`
   - `linux-desktop`
   - `wsl2-engine`: Docker Engine installed in the distro
   - `wsl2-desktop`: Docker Desktop's WSL integration
   - `macos-desktop`
   - `windows-desktop`

   The engine records the result as a `platform` evidence record, and rules read it from the evidence view; rules still import only `evidence` (§4.1). Examples:
   - `host.docker.internal` works out of the box on Docker Desktop, so WR011 must never fire there. On Docker Engine it needs a `host-gateway` mapping.
   - On Docker Desktop, `network_mode: host` puts the container in the VM's network namespace, not the developer's machine's.
     - Since Desktop 4.34, an opt-in "Enable host networking" setting forwards TCP and UDP (only) between the machine and such containers. Detect whether it's active rather than assuming either way.
     - Under ECI, host networking is refused outright.
   - Under WSL2, host-level evidence describes the WSL2 VM. On `wsl2-desktop`, rules that need Windows-side host state (WR012's host listeners, WR013's host routes) record a gap instead of drawing conclusions from the VM's state.
   - WSL2 detection: `-microsoft-standard` in `/proc/sys/kernel/osrelease` is only a hint (current kernels end in `-microsoft-standard-WSL2`). Containers on a WSL2 kernel report the same string, and custom kernels may not. Confirm with `/proc/sys/fs/binfmt_misc/WSLInterop`, and check that whyreach isn't itself running inside a container.
5. **Testing.** GitHub-hosted runners can't be the macOS/Windows gate.
   - macOS runners don't ship Docker. The Apple-silicon ones can't run it at all (no nested virtualization). The Intel labels can run it in a Lima VM only on a best-effort basis, and they are being phased out.
   - Windows runners ship Docker for Windows containers only. Linux containers inside WSL2 on `windows-2025` are possible but unreliable.

   Linux CI stays the release gate. macOS, Windows and WSL2 are validated with manual lab runs or self-hosted runners.
6. **Launching from Windows MCP clients.**
   - Use `wsl.exe -d <distro> --exec /abs/path/whyreach mcp serve`. Without `--exec`, the command runs through a non-login shell and misses PATH entries set in profile files.
   - The server runs as the distro's default user.
   - Env vars in the client's MCP config don't cross into WSL unless they're listed in `WSLENV`, so pass settings as flags.
   - The server must exit promptly on stdin EOF.
   - No MCP client documents this pattern, so test each client.

**Host-level checks on macOS and Windows** need separate collectors:
- **macOS:** routing sockets (`golang.org/x/net/route`) and sysctl.
- **Windows:** the IP Helper API, with `GetExtendedTcpTable` for listeners and `GetBestRoute2` for route lookup. `golang.org/x/sys/windows` doesn't wrap either function, so they'd be bound through `windows.NewLazySystemDLL("iphlpapi.dll")`.

Build them only if users ask.

---

## 4. LLD

### 4.1 Repository layout

```
whyreach/
├── cmd/whyreach/          main.go: wires cli + mcpserver
├── internal/
│   ├── cli/                cobra commands; text/json rendering
│   ├── mcpserver/          tool registration, In/Out types, annotations
│   ├── policy/             tiers, target policy, rate limiter, audit log
│   ├── engine/             workflows (diagnose_connection, …), deadlines
│   ├── target/             "from"/"to" grammar → typed Endpoint / ContextRef
│   ├── evidence/           Evidence, Store, View, IDs, typed payloads
│   ├── rules/              Rule interface, registry, wr0xx_*.go, testdata/
│   ├── collect/
│   │   ├── host/           netlink links/addrs/routes/neigh; /proc/net parsers
│   │   └── docker/         allowlisted Engine API client; minimal typed structs
│   ├── executor/           Executor interface: host, probecontainer, netns
│   ├── probe/              pure probes (dns, tcp, listeners) + hidden `__probe` entrypoint
│   ├── report/             renderers, redaction, bundle writer
│   ├── config/             XDG config load + validation
│   └── platform/           capability + platform detection (root? docker? API? arch? Desktop/WSL2?)
├── test/
│   ├── lab/<scenario>/     compose.yaml + scenario.yaml (expected findings)
│   └── e2e/                harness that runs the lab (build tag: lab)
├── docs/
│   ├── adr/                architecture decision records (0001-execution-contexts.md, …)
│   ├── research/           background research (failure-signatures.md)
│   └── rules/WR001.md …    one page per rule (pitfall, evidence, fix), ShellCheck-wiki style
├── spikes/                 M0 throwaway spikes; not product code (ADR 0001)
├── Makefile · go.mod · .golangci.yml · .goreleaser.yaml
└── README.md · SECURITY.md · CONTRIBUTING.md · LICENSE (Apache-2.0)
```

**Import direction** (enforce it with depguard or an import test):
- `cli` and `mcpserver` → `policy` → `engine` → { `rules`, `collect/*`, `executor`, `evidence` }
- `rules` → `evidence` only
- `executor` → `probe`
- Nothing imports `cli` or `mcpserver`.

### 4.2 Core types (sketch)

```go
// ---- evidence ----
type Status string // ok | failed | timeout | unsupported | permission_denied | skipped | error

type ContextRef struct {
    Kind      string // "host" | "container"
    Container string // short id; empty for host
    Name      string // "worker", "compose:shop/worker"
    NetnsID   uint64 // netns inode: proves two checks ran in the same place
    Executor  string // "host" | "probe-container" | "netns"
}

type Evidence struct {
    ID          string        // "ev-07", stable within one diagnosis
    Kind        Kind          // docker.container, docker.network, netns.listeners,
                              // probe.dns, probe.tcp, host.route, host.links, …
    Context     ContextRef
    Subject     string        // "api:8080", "network:shop_default"
    Status      Status
    ObservedAt  time.Time
    Duration    time.Duration
    Data        any           // typed payload per Kind (below)
    Err         *EvidenceErr  // {Code, Message, Errno}
    Limitations []string
    Source      string        // "docker GET /containers/{id}/json", "/proc/net/tcp6 via probe-container"
}

type TCPProbe  struct { Addr netip.AddrPort; Outcome string /* connected|refused|timeout|unreachable|reset|error */; Errno string; RTT time.Duration }
type DNSProbe  struct { Name, Server, Rcode /* NOERROR|NXDOMAIN|SERVFAIL|REFUSED|TIMEOUT */, Via /* hosts|dns */ string; Answers []netip.Addr }
type Listeners struct { Sockets []Socket } // Proto, Local netip.AddrPort, Family, State
type Container struct {
    ID, Name, Image, State, Health string
    StartedAt    time.Time
    RestartCount int
    Compose      *ComposeRef     // project, service (from labels)
    NetworkMode  string          // bridge | host | none | container:<id> | <network>
    Networks     []NetAttachment // network, IPv4, IPv6, gateway, aliases, DNSNames
    Ports        []PortMap       // container port/proto → host ip:port
    ExtraHosts   []string
}

// ---- diagnosis ----
type Diagnosis struct {
    ID            string
    SchemaVersion int          // 1
    Question      Question     // parsed from / to / port / proto
    Verdict       string       // cause_identified | likely_cause | inconclusive | no_problem_reproduced
    Summary       string       // one sentence
    Findings      []Finding    // ranked
    Facts         []Fact       // {Text, Evidence []string}
    Gaps          []Gap        // {What, Why (permission|unsupported|timeout), HowToEnable}
    NextChecks    []NextCheck  // {Why, Tool, Args}: machine-actionable
    SideEffects   []string     // e.g. ephemeral probe containers
    ChangesMade   bool         // always false
    Evidence      []Evidence
    Timing        Timing
}

type Finding struct {
    RuleID        string   // "WR002"
    Title         string
    Confidence    string   // high | medium | low
    Explanation   string
    Supporting    []string // evidence IDs
    Contradicting []string
    Fix           string   // advice only; never executed
    DocURL        string
}
```

### 4.3 Target grammar

- **`from`** (defaults to `host`): `host`, `container:<name|id>`, or `service:<compose-service>[@<project>]`
- **`to`**: `<host>:<port>` or `tcp://<host>:<port>`. The host can be a container name, a Compose service, an alias, a DNS name, an IPv4 address, `[IPv6]`, `localhost`, or `host.docker.internal`.
- **Resolution order:** first look for a matching container, service or alias on the source's networks, then fall back to DNS. Resolve the source's *effective* network namespace first: `network_mode: host`, `container:X` and `none` all change it.
- **Rejected:** CIDRs, ranges, port lists, wildcards, and URLs that contain credentials.

### 4.4 Engine

The engine is a staged pipeline per workflow, not a generic DAG engine (YAGNI): **resolve → collect → probe → evaluate → compose** (see §3.4).

- **Parallelism:** `errgroup` with a limit of 4 during the collect stage.
- **Timeouts:**

  | Operation | Timeout |
  |---|---|
  | Docker API call | 3 s |
  | DNS lookup | 2 s, with 1 retry |
  | TCP connect | 2 s |
  | probe-container run | 8 s |
  | whole diagnosis | 15 s |

  Cancellation propagates from the MCP or CLI context. When the deadline hits, the engine evaluates whatever evidence it has and marks the rest as `timeout`.
- **Verdict**, decided in this order:
  1. The TCP connect from the source succeeded → `no_problem_reproduced`, with next checks for app-level, TLS or timing problems. Any findings that remain, such as advisories, are listed as "also found".
  2. The primary finding (§4.5) is high → `cause_identified`.
  3. The primary finding is medium → `likely_cause`.
  4. Otherwise → `inconclusive`, with gaps.

### 4.5 Rules

```go
type Rule interface {
    ID() string                         // "WR002": permanent, never renumbered or reused
    Layer() Layer                       // its place in the precedence order (table below)
    Requires() []evidence.Kind          // missing → not evaluated → becomes a Gap
    Supersedes() []string               // findings it makes redundant, e.g. WR004 supersedes WR005 and WR016
    Evaluate(v evidence.View) []Finding // pure: no I/O, no clock, no randomness
}
```

**Every rule ships with:**
- fixtures in `rules/testdata/WRxxx/`, including at least one case where the rule must **not** fire
- a lab scenario in `test/lab/wrxxx-<slug>/`
- a doc page at `docs/rules/WRxxx.md`

**Confidence levels.** A rule's confidence depends on how much of its key evidence (§4.6) is present. The catalog's **Probe?** column, taken from the experiments (ADR 0002), says what a probe adds:
- **high:** the evidence settles the cause.
  - Rules marked Probe? "no" are settled by metadata and listeners alone, so they reach high in the default configuration, with no probe and no Docker write. Example: api's only listener for the port is 127.0.0.1:8080, and worker targets api's network address (WR002). A refused connect from worker confirms it but isn't needed.
  - Rules marked "partly" or "yes" also need a probe result that matches the cause.
- **medium:** the cause is inferred, with one piece of evidence missing. Example: a "partly" rule whose DNS check couldn't run because tier 2b is off and whyreach isn't root.
- **low:** circumstantial evidence only. Example: a timeout and nothing else.

Contradicting evidence lowers the confidence by one level. A rule marked "yes" whose probe can't run isn't evaluated: it becomes a gap that says how to enable the check.

**Precedence (ADR 0002).** Each rule belongs to a layer. The layers follow the order a connection depends on: the destination has to be up before naming matters, naming comes before the path, and the path comes before the listener.
- The **primary finding** is the highest-confidence finding in the earliest layer that has one.
- Findings that only follow from it are dropped through `Supersedes()`.
- Independent findings in later layers stay, listed as "also found" in fix order. Example: "after you connect the networks, api still only listens on loopback".

| Layer | Question | Rules, in evaluation order |
|---|---|---|
| 1. Destination | Is the destination container there and running? | WR008, WR010 |
| 2. Addressing | Is the source aiming at the right thing? | WR007, WR011, WR023, WR006, WR019, WR024 |
| 3. Naming | Can the source reach the destination by name at all? | WR004, WR009, WR005, WR020 |
| 4. Path | Can packets get there? | WR015, WR013, WR021, WR022, WR016 |
| 5. Listener | Is the right socket listening? | WR002, WR012, WR014, WR003, WR001 |
| 6. Advisory | Could something break a working connection? | WR017, WR018 |

Suppression pairs from the experiments:

| Primary finding | Suppresses | Why |
|---|---|---|
| WR004 | WR005, WR016 | Traffic between networks times out. |
| WR008 | WR001, WR005, WR016 | A restarting container has no IP. |
| WR007, WR002 | WR001 | — |
| WR006 | WR003 | — |
| WR015, WR024 | WR016 | — |
| WR013 | WR016 | The route sends the traffic somewhere else. Expected but not reproduced yet (E9 only looked the route up); confirm in v0.2. |

### 4.6 Rule catalog

Sources for the columns:
- **Rank:** real-world frequency, from `docs/research/failure-signatures.md`.
- **Probe?** whether the rule needs the probe container, from `docs/research/rule-experiments.md`.
- **Release:** the build order decided in ADR 0002.

**v0.1 is 14 rules:** WR001–WR012, WR019 and WR020.

| ID | Pitfall | Layer | Key evidence | Probe? | Rank | Release |
|---|---|---|---|---|---|---|
| WR001 | Nothing is listening on the port in the destination's netns | 5 | listeners (no match) + refused | no | — | v0.1 · M2 |
| WR002 | Service bound to loopback only (127.0.0.1 or ::1) | 5 | loopback-only listeners | no | 11 | v0.1 · **M1** |
| WR003 | Service listens on a different port (suggest that port) | 5 | listeners | no | — | v0.1 · M2 |
| WR004 | The two containers share no network (e.g. separate Compose projects) | 3 | network membership, Compose project labels | no | 2 | v0.1 · **M1** |
| WR005 | The name matches no container, service or alias on the source's networks (suggest the closest). Decided from metadata, **not** from the DNS rcode | 3 | network members (+ DNS view) | partly | 8 | v0.1 · M2 |
| WR006 | The host-published port is used between containers, or a published port is reached through the host's address | 2 | port mappings + target | no | 17 | v0.1 · M2 |
| WR007 | `localhost`/127.0.0.1 used inside a container to reach another container or the host. The fix differs: the service name, or `host.docker.internal` | 2 | target + source listeners + other containers' and host listeners | no | **1** | v0.1 · **M1** |
| WR008 | The destination is not running, is restarting, or is unhealthy. Checked before any probe | 1 | state, health, RestartCount | no | not measured | v0.1 · M2 (first) |
| WR009 | Default `bridge` network: containers can't resolve each other's names | 3 | network name and driver | no | 12 | v0.1 · M2 |
| WR010 | Startup race: the destination isn't ready yet | 1 | health `starting`, StartedAt, listeners | no | 4 | v0.1 · M2 |
| WR011 | `host.docker.internal` doesn't resolve on Docker Engine (no `host-gateway` mapping). Never fires on Docker Desktop | 2 | ExtraHosts + platform (+ DNS) | partly | 7 | v0.1 · M2 |
| WR012 | A host service is bound to 127.0.0.1, so containers can't reach it (Linux Engine, and WSL2 without Desktop) | 5 | host listeners + target is the host | no | 5 | v0.1 · M2 |
| WR013 | A Docker subnet overlaps a VPN or LAN route | 4 | host route lookup + network subnets | no | 15 | v0.2 |
| WR014 | IPv6/IPv4 mismatch: `localhost` resolves to `::1` first, but the listener is IPv4-only | 5 | DNS answers + listener families | yes | 18 | v0.2 |
| WR015 | `internal: true` network, but the target is outside it | 4 | network Internal flag | no | not measured | v0.2 |
| WR016 | Timeout means a silent drop. Last resort: suppressed when WR004, WR008, WR013, WR015 or WR024 explains the timeout | 4 | TCP timeout + route | yes | not measured | v0.2 |
| WR017 | MTU mismatch. Advisory until a size probe confirms a stall | 6 | link MTUs | no | 16 | v0.3 |
| WR018 | Proxy env vars intercept traffic. Reads env var **keys only**, never values | 6 | env keys | no | not measured | v0.3 |
| WR019 | Port not published, or published on another host address (host → container) | 2 | PortBindings + container listeners | no | 6 | v0.1 · M2 |
| WR020 | The container's upstream DNS fails: internal names resolve, external ones time out | 3 | DNS from the source + `resolv.conf` `ExtServers` | yes | 3 | v0.1 · M2 |
| WR021 | The host firewall rejects container-to-host traffic (EHOSTUNREACH to the host) | 4 | errno + host listener (+ firewall rules, needs root) | yes | 9 | v0.2 |
| WR022 | No outbound NAT or forwarding | 4 | `ip_forward`, daemon firewall settings | yes | 10 | v0.3 |
| WR023 | Docker Desktop: `network_mode: host` means the VM | 2 | platform + NetworkMode | no | 14 | v0.3 · M7 |
| WR024 | Stale or hard-coded container IP: no container owns the address, or the source's sockets point at an old IP | 2 | members' IPs + source socket table + EHOSTUNREACH | partly | 13 | v0.2 |
| WR025 | Advertised-address redirect (Kafka and similar) | — | — | — | 19 | deferred (ID reserved) |

### 4.7 Executors

```go
type Executor interface {
    Name() string
    // Run executes a batch of probe specs inside `where`'s netns and returns evidence.
    Run(ctx context.Context, where evidence.ContextRef, specs []probe.Spec) ([]evidence.Evidence, error)
}
```

- **`host`** calls the `probe` package in-process.
- **`probecontainer`**:
  1. Make sure the image `whyreach-probe:<ver>` exists. If it doesn't, import the binary's own executable as a scratch image (`POST /images/create?fromSrc=-`, setting the label `io.whyreach.probe=1` through `changes`), and report the import in `side_effects`. Check that the daemon's architecture (from `/version`) matches.
  2. Create the container with the hardened config from §3.3 (no AutoRemove), start it, and wait for it under the timeout (`wait?condition=not-running`).
  3. Read the logs: stdout is one JSON evidence object per line. Without a TTY the log stream is **multiplexed with 8-byte frame headers**, so demux it.
  4. Remove the container (`DELETE …?force=1`). This runs on every path, timeouts and cancellation included, under its own short context, so a cancelled diagnosis still cleans up.

  There is one container per (diagnosis, context), and all specs for that context run in it as a batch.
- **`netns`**:
  - Used only on `linux-engine` and `wsl2-engine` (§3.7). First verify that the PID belongs to the target container, for example by checking that `/proc/<pid>/cgroup` contains the container ID. On Docker Desktop, `State.Pid` is a PID in another namespace and can match an unrelated local process, so a blind `setns` could enter the wrong namespace.
  - Call `runtime.LockOSThread()`, open `/proc/<pid>/ns/net`, and call `unix.Setns(fd, CLONE_NEWNET)`. Create the sockets there; a socket keeps the netns it was created in.
  - Restore the original netns before unlocking. If the restore fails, never unlock; Go then terminates the thread.
  - The mount namespace is **not** switched, so read the container's resolver config through `/proc/<pid>/root/etc/{resolv.conf,hosts}`.
- **Probe mode:** the same binary has a hidden `whyreach __probe --spec '<json>'` subcommand. It writes JSON lines and exits non-zero only on an internal error.

### 4.8 Collectors and probes

- **`collect/host`** uses `vishvananda/netlink` for links, addresses, `RouteGet(dst)` and neighbours. It reads listeners from `/proc/net/{tcp,tcp6,udp,udp6}`, where addr:port is hex and state `0A` means LISTEN. It never shells out to `ip` or `ss`.
- **`collect/docker`** uses `net/http` over the unix socket:
  - A `RoundTripper` holds an **allowlist of method + path pattern**. "GET-only" alone isn't enough: `GET /containers/{id}/export` dumps an entire filesystem.
  - Default allowlist: `GET /version`, `/containers/json`, `/containers/{id}/json`, `/networks`, `/networks/{id}`.
  - The probe client is constructed separately with its own allowlist: create, start, wait, logs and delete for containers, plus image inspect and import.
  - The API version is negotiated through `/version`.
  - Responses are decoded into minimal structs that we own; unknown fields are ignored.
  - **No Docker SDK.**
- **`probe/dns`** uses a `miekg/dns` client pointed at the resolver from `resolv.conf`. This gives the real rcode, so NXDOMAIN, SERVFAIL and timeout can be told apart; `net.Resolver` hides that difference. It checks `/etc/hosts` first, as nsswitch's `files dns` order does, and records which path answered. Known limitation: the app's libc (glibc or musl) may order A and AAAA results differently.
- **`probe/tcp`** uses `net.Dialer{Timeout}` and classifies errors with `errors.Is(err, syscall.ECONNREFUSED)` and similar checks. It connects and then closes, and never sends a payload.
- **`probe/listeners`** reads `/proc/net/tcp{,6}` from inside the context.

### 4.9 Policy and permission tiers

| Tier | Capability | Default |
|---|---|---|
| 0 | Read host network state (netlink, /proc/net) | on |
| 1 | Bounded DNS and TCP probes | on, limited by policy |
| 2a | Read Docker metadata (allowlisted GETs) | on if the socket is reachable |
| 2b | Ephemeral probe containers | **off**; enable in config or approve through elicitation |
| 3 | Root-only checks: entering a netns, reading the firewall | only when running as root |
| 4 | Any change to routes, firewall, interfaces, DNS or containers | never |

**Probe target policy:**
- One host:port per call. No CIDRs, ranges, lists or wildcards.
- Blocked by default: `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200` (cloud metadata and link-local addresses).
- An optional allowlist (`loopback`, `rfc1918`, `docker`, or explicit CIDRs) restricts targets further.
- A token bucket allows 30 probes per minute, and a name resolves to at most 4 addresses.

**Hard rule:** tool arguments can only narrow permissions. Tiers come from the user's config or from MCP elicitation, never from the agent.

**Audit log:** JSON Lines at `$XDG_STATE_HOME/whyreach/audit.jsonl`. Each entry records the tool, its sanitized arguments, duration, status and side effects.

### 4.10 MCP surface (4 tools)

| Tool | Input | Output |
|---|---|---|
| `diagnose_connection` | `to`, `from?`, `expect?` (`connect`) | Diagnosis (compact) |
| `inspect_environment` | `scope`: `host`, `container:<x>`, or `network:<x>` | compact facts (no raw dumps) |
| `run_probe` | `kind` (`dns`, `tcp` or `listeners`), `target`, `from?` | a single Evidence |
| `save_report` | `diagnosis_id`, `redact?` (on by default) | path + redaction summary |

- Use the official Go SDK with typed handlers (`mcp.AddTool` with In/Out structs). That gives input validation, an `outputSchema` and `structuredContent` automatically. Also return a short text summary for clients that ignore structured content.
- **Annotations must be honest:**
  - `destructiveHint: false` and `idempotentHint: true`
  - `openWorldHint: true` on tools that send probes
  - `readOnlyHint: true` *unless tier 2b is enabled*; probe containers modify the environment briefly
- Tool failures are returned as results with `isError: true`, so the model can correct itself. They are not protocol errors.
- Tool descriptions say *when* to use the tool. Example: "Use this first when one service can't reach another."
- **Structured first (ADR 0001).** Claude Code shows the model the `structuredContent`, not the text summary. The structured `Diagnosis` therefore:
  - leads with `verdict` and `summary`
  - holds short facts with evidence IDs
  - stays within about 1.5k tokens

  Raw evidence goes to report bundles.
- **Discoverable names.** Clients may defer MCP tools and find them by search, so tool names and descriptions use the words an agent would search for: network, connect, docker, diagnose.
- `NextChecks` name these tools and include ready-to-use arguments.

### 4.11 CLI

```
whyreach [--from container:worker] api:8080           # short form of `whyreach diagnose`
whyreach diagnose [--from container:worker] api:8080 [--json] [--report]
whyreach inspect host | container <name> | network <name>
whyreach probe tcp|dns|listeners <target> [--from …]
whyreach report list | show <id> | export <id> [--redact-private]
whyreach rules list | explain WR002
whyreach doctor          # self-check: capabilities, permissions, Docker API version
whyreach mcp serve       # stdio
```

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | no problem reproduced |
| 1 | cause or likely cause found |
| 2 | inconclusive |
| 3 | usage or policy error |
| 4 | internal error |

### 4.12 Reports and redaction

**Bundle location:** `$XDG_DATA_HOME/whyreach/reports/<UTC-ts>-<id>/`, with the directory at `0700` and files at `0600`. It contains:
- `manifest.json`: version, schema, redaction summary, sha256 checksums
- `diagnosis.json`
- `evidence.jsonl`
- `report.md`

**Redaction** is on by default for exports:
- Public IPs, hostnames, MACs and container IDs are replaced with stable pseudonyms per report (`ip-1`, `host-2`). They are derived with an HMAC under a random per-report key, so correlations survive redaction.
- RFC1918 addresses are kept unless `--redact-private` is set.

**Never collected:** env var values, file contents other than `resolv.conf` and `hosts`, and packet payloads.

### 4.13 Config

`$XDG_CONFIG_HOME/whyreach/config.toml`

```toml
[permissions]
docker = true
probe_containers = false        # tier 2b

[probe]
allow = ["loopback", "rfc1918", "docker"]
rate_per_minute = 30

[timeouts]
diagnosis = "15s"

[report]
redact_private = false
```

### 4.14 Errors and logging

- **Error codes:** `invalid_argument`, `policy_denied`, `docker_unavailable`, `permission_denied`, `not_found`, `timeout`, `unsupported`, `internal`.
- **Logging:** `log/slog` as JSON, to **stderr only**. In `mcp serve`, stdout carries the protocol, so a stray `fmt.Println` breaks the session.
- **Errors:** wrap them with `%w` and keep the syscall errno; rules depend on it.

### 4.15 Cross-platform build rules

- Files that use netlink, `/proc` or `setns` carry `//go:build linux`. Each such package has an `_other.go` stub that returns `Status: unsupported` with a gap explaining why.
- `probe/tcp` and `probe/dns` are portable; the host executor uses them on every OS. `probe/listeners` is Linux-only. The probe entrypoint (`__probe`) always runs inside a Linux container, and stays cgo-free so it builds statically for amd64 and arm64.
- `make cross` compiles the whole module for darwin and windows (amd64 and arm64). It runs in CI from M0, so portability can't break silently. CI also runs `make vuln` (govulncheck), so a standard-library or dependency advisory in code we call can't go unnoticed either.
- Config, report and audit paths come from one helper: the XDG directories from §4.9 (audit), §4.12 (reports) and §4.13 (config) on Linux, and the platform's standard user directories on macOS and Windows.

---

## 5. EXAMPLES

**CLI (target output)**

```
$ whyreach diagnose --from container:worker api:8080
✗ worker → api:8080 — cause identified (high)

WR002  api listens only on 127.0.0.1:8080 inside its container
       Other containers can't reach a loopback-bound socket.
  facts  • worker and api share network shop_default          [ev-02 ev-03]
         • "api" → 172.20.0.4 via Docker DNS 127.0.0.11        [ev-05]
         • connect 172.20.0.4:8080 from worker: refused (3 ms) [ev-06]
         • api listeners: 127.0.0.1:8080/tcp                   [ev-04]
  fix    bind to 0.0.0.0:8080 (e.g. --host 0.0.0.0) and restart api
  docs   docs/rules/WR002.md

side effects: 1 ephemeral probe container (removed) · changes made: none
```

**MCP `structuredContent` (trimmed)**

```json
{
  "id": "dg-01JD7Q…",
  "verdict": "cause_identified",
  "summary": "api is bound to loopback; worker cannot reach it.",
  "findings": [{
    "rule_id": "WR002", "confidence": "high",
    "supporting": ["ev-04", "ev-06"],
    "fix": "Bind the server to 0.0.0.0:8080 and restart api."
  }],
  "gaps": [],
  "next_checks": [{
    "why": "confirm after the fix",
    "tool": "run_probe",
    "args": {"kind": "tcp", "from": "container:worker", "target": "api:8080"}
  }],
  "side_effects": ["ephemeral probe container wr-probe-3f2a (removed)"],
  "changes_made": false
}
```

**Lab scenario**

```yaml
# test/lab/wr002-loopback-bind/scenario.yaml
from: container:worker
to: api:8080
expect:
  verdict: cause_identified
  top_rule: WR002
  confidence: high
  must_not_fire: [WR004, WR005]
```

---

## 6. Testing

### 6.1 Unit tests
- **What they cover:**
  - parsers: `/proc/net`, the target grammar, `resolv.conf`
  - rules: fixtures plus must-not-fire cases
  - redaction
  - policy: table-driven, covering every target shape that must be denied
- **Requirements:** no Docker, no network and no root. `go test ./...` must pass on any Linux machine.

### 6.2 Golden tests
They cover the text, Markdown and MCP-text renderers, and the MCP `structuredContent` JSON, which is what agents actually read (ADR 0001). Regenerate the golden files with `go test ./internal/report/... -update`.

### 6.3 Lab (integration)
- **Layout:** each scenario is `test/lab/<scenario>/`, containing `compose.yaml` and `scenario.yaml`.
- **Harness** (build tag `lab`):
  1. `docker compose -p whyreach-lab-<name>-<rand> up -d --wait`
  2. run the engine
  3. assert on the result
  4. `down -v`
- Unique project names let scenarios run in parallel without touching any other containers.
- **Starting point:** the experiment scenarios: E1–E6 and E8 are Compose files in `spikes/experiments/`, and E7 and E9 run inline in `spikes/experiments.sh`. M1 promotes the slice scenarios first (ADR 0002). Note that `up --wait` would hang on the slow-start and crash-loop scenarios, so those need their own wait conditions.
- **netns variants** need root: `sudo -E go test -tags lab,privileged …`.
- **CI** runs on GitHub Actions Ubuntu runners, which have Docker and sudo.
- **v0.1 scenario set:**
  - one scenario per MVP rule
  - the healthy control
  - two scenarios that must stay inconclusive, e.g. listeners unreadable plus a timeout

### 6.4 Agent benchmark (the validation experiment)
For each lab scenario, run a headless agent twice:
- **(a)** with shell only
- **(b)** with whyreach's MCP tools only, no shell

Record whether it found the right root cause, how many tool calls and tokens it used, the wall-clock time, and any unsafe commands it attempted. If (b) isn't clearly better on at least half the scenarios, narrow the scope before v1.0. Publish the results table; it doubles as the launch post.

---

## 7. Milestones

| M | Scope | Exit criterion |
|---|---|---|
| **M0** (≤1 wk) | `git init` and scaffold (Makefile, CI, lint, and a `make cross` compile check for macOS and Windows). Spikes: (1) the privilege matrix; (2) a probe-container proof: `resolv.conf`/`hosts` sharing, `/proc/net` in a shared netns, importing a scratch image; (3) an MCP Go SDK hello-world tool with structured output, called from Claude Code. Collect the top ~20 real failure signatures. | Spike results written up in `docs/adr/0001-execution-contexts.md`. ✅ Done 2026-11-13 |
| **M1** (2–3 wk) | Evidence types, the allowlisted Docker client, the probe-container executor, probes, listeners read from the host (the containers' through `/proc/<pid>`, plus the host's own, which WR007 needs to choose its fix), rule layers and precedence, the slice rules WR007/WR004/WR002 plus the healthy control (ADR 0002), CLI `diagnose` | The §2.3 vertical slice passes in the lab |
| **M2** (2 wk) | MCP server (4 tools), policy, audit log, host↔container flows (`--from host`, and containers reaching host services) with the host collectors they need, the rest of the v0.1 rules in ADR 0002's order (WR008 first, then WR020, WR010, WR012, WR019, WR011, WR005, WR009, WR006, WR003, WR001), `doctor` | An agent diagnoses every MVP lab scenario through MCP alone |
| **M3** (1–2 wk) | netns executor (root) | The same lab passes with the netns executor and no Docker writes |
| **M4** (1–2 wk) | Reports and redaction, `docs/rules/*`, goreleaser builds (linux amd64/arm64), checksums and attestations, a container image, MCP Registry listing | A new user installs, connects a client, and diagnoses the demo using only the docs |
| **M5** | Benchmark (§6.4) and launch | Results published |
| **M6** (v0.2) | Windows via WSL2 (`wsl2-desktop` and `wsl2-engine`): platform detection and platform-aware rules (WR011 must not fire under Docker Desktop), host evidence labelled as the WSL2 VM, setup docs for launching through `wsl.exe` (§3.7). CI mode: an example GitHub Actions step that runs `whyreach diagnose --from <source> <target> --json` when Compose tests fail (JSON output and exit codes already ship in v0.1). The v0.2 rules: WR015, WR024, WR014, WR013, WR016, WR021 | The lab passes inside WSL2 in a manual run; the CI example diagnoses a deliberately broken Compose test |
| **M7** (v0.3) | Native macOS and Windows builds for container checks: embedded Linux probe binaries, Docker endpoint discovery, platform-aware rules for `macos-desktop`, `windows-desktop` and `linux-desktop`, and running the container image (§3.5) on Docker Desktop. Docker Desktop for Linux. The v0.3 rules: WR017, WR018, WR022, WR023 | Manual lab runs pass on Docker Desktop for macOS, Windows and Linux |

---

## 8. DOCUMENTATION

- MCP specification (tools, structured output, annotations, elicitation): https://modelcontextprotocol.io/specification
- MCP Go SDK (official, v1.x): https://github.com/modelcontextprotocol/go-sdk · API: https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp
- Docker Engine API reference: https://docs.docker.com/reference/api/engine/
- Docker networking (including the `container:` network mode): https://docs.docker.com/engine/network/ · bridge driver: https://docs.docker.com/engine/network/drivers/bridge/
- Compose networking: https://docs.docker.com/compose/how-tos/networking/
- Go netlink and netns: https://github.com/vishvananda/netlink · https://github.com/vishvananda/netns
- Go DNS client: https://github.com/miekg/dns
- `/proc/net/tcp` format: https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
- Man pages for setns(2), namespaces(7), network_namespaces(7), resolv.conf(5), hosts(5) and tcp(7): https://man7.org/linux/man-pages/
- Prior art:
  - `nicolaka/netshoot`, the manual version of the probe-container idea: https://github.com/nicolaka/netshoot
  - `rhel-lightspeed/linux-mcp-server`, a general read-only Linux MCP server written in Python: https://github.com/rhel-lightspeed/linux-mcp-server
  - k8sgpt, deterministic analyzers with AI on top, for Kubernetes: https://github.com/k8sgpt-ai/k8sgpt
  - the ShellCheck wiki, the model for one documentation page per rule ID: https://www.shellcheck.net/wiki/
  - Docker Gordon: https://docs.docker.com/ai/gordon/

---

## 9. OTHER CONSIDERATIONS (gotchas)

**Docker networking semantics**
- The DNS rcode for an unknown name depends on the host's resolver, not on Docker. Behind a systemd-resolved stub, single-label names come back SERVFAIL; elsewhere they come back NXDOMAIN. Decide "name not found" from Docker metadata (rule experiments E1, E2).
- Connecting by IP to a container on another network times out (a silent drop) rather than being refused.
- Networking semantics differ between Linux Docker Engine, Docker Desktop and WSL2 (§3.7). A rule that is correct on Linux can be wrong on Docker Desktop, so rules that depend on the platform must check it.
- Inside a container, `localhost` refers to that container. Every message and rule must say *which* network namespace an address belongs to.
- Docker's embedded DNS (127.0.0.11) exists only on user-defined networks, and only inside the container's network namespace. Looking up a service name from the host means nothing.
- A Compose service name is not the container name (`shop-api-1`). Match container names, service names, `Aliases` and `DNSNames`.
- A published port such as `8081:8080` applies only to traffic arriving from the host side. Container-to-container traffic uses the container port.
- Docker Engine 28 and later block direct access to container IPs from other hosts by default. Recent Engine versions can also use an nftables firewall backend, so don't assume the iptables `DOCKER` chains exist. Rules have to take the Engine version into account.

**Probes and evidence**
- Go and `setns`: lock the OS thread. A socket stays in the netns it was created in. Goroutines started inside don't inherit the netns. The mount namespace isn't switched, so reading `/etc/resolv.conf` would give you the host's file.
- On this machine `ping_group_range` is `1 0`, which disables unprivileged ICMP. Use TCP connect probes and never require ICMP.
- `ss -p` (mapping a socket to a PID) needs root for processes owned by other users. Whether a listener exists, and its bind address, do not.
- Refused (an RST), timeout (packets dropped) and unreachable (ICMP or no route) are different results. Never merge them, and keep the errno.
- A successful probe from whyreach doesn't prove that the app's own client works: proxy env vars, TLS, IPv6 ordering and libc behaviour can all differ. Say so in `limitations`.
- Containers restart and change IP. Re-resolve everything in every diagnosis, and never cache container IPs between diagnoses.
- Distroless and scratch images are the *common* case, not an edge case. Never depend on tools being present inside a target container.
- Docker's embedded DNS listens on `127.0.0.11:<random port>` inside every container on a user-defined network. Listener-based rules must ignore it (ADR 0001).
- Go's `LookupNetIP` returns `/etc/hosts` entries as IPv4-mapped IPv6 (`::ffff:10.9.8.7`). Call `Unmap()` before comparing or reporting addresses.
- A container's `resolv.conf` contains the host's DNS search domain and Docker's `ExtServers` comment. Redact the search domain in reports, since it can identify the user's organisation. Use the comment as DNS evidence.
- Look up host routes through the kernel (netlink `RouteGet`). Machines with VPN clients often route through non-main policy-routing tables.

**Docker API mechanics**
- Container logs without a TTY are multiplexed, so demux the 8-byte frame headers.
- A `container:` network mode needs the target to be running. If it isn't, report WR008 instead of failing obscurely.

---

## 10. Open questions (resolve in M0 unless marked otherwise)

1. **Resolved: yes** (ADR 0001). A `docker`-group user can read a root-owned container process's `/proc/<pid>/net/tcp{,6}`, so on Linux Engine listener checks need no Docker write.
2. **Resolved: yes** (ADR 0001). The probe and the target have identical `ResolvConfPath`, `HostsPath` and `HostnamePath`, and markers set only on the target were visible in the probe.
3. Which MCP clients support elicitation or input-required results for tier-2b consent? The fallback is the config file. (Resolve in M2, with the MCP server.)
4. **Resolved: import our own binary** (ADR 0001). A 3.3 MB import took 78 ms and an ~18 MB import 69 ms, so Linux needs no registry image. Revisit for M7, when the macOS and Windows builds embed Linux probe binaries.
5. **Resolved: renamed from NetDoctor to whyreach** (2026-11-13). Rule IDs changed from `NDxxx` to `WRxxx` at the same time.
   - **Why the old name had to go** (details in `docs/research/failure-signatures.md`):
     - Riverbed Technology, a network-performance vendor, holds a US trademark "NETDOCTOR" for software (serial 90554897, filed 2021-03-02). Trademarkia and uspto.report list it as registered.
     - A Go network-diagnosis tool for Kubernetes, `kosmos-io/netdoctor`, uses the exact name.
     - The PyPI name was taken.
   - **Why whyreach:** it was free on npm, PyPI, Homebrew core and the MCP Registry, and no GitHub repository used it. No trademark search was done; this is not legal advice.
   - **What wasn't renamed:** the project folder on the dev box is still `NetDoctor/`; rename it outside a running session if wanted. The original proposal keeps the old name as a historical document.
6. **Resolved: Apache-2.0** (`LICENSE` added in M0).
7. Does the probe container work on Docker Desktop with Enhanced Container Isolation turned on (common on business plans)? Docker's docs are silent. Sysbox, which ECI is built on, supports container-to-container network sharing, so it's expected to work, but it must be tested. (Resolve in M6, when Docker Desktop's WSL integration is first supported.)
8. Which runtimes besides Docker Engine (OrbStack, Colima, Rancher Desktop with moby, Podman) pass the lab unchanged? (Resolve in M7.)
9. How do we test WR021 (host firewall reject) and confirm WR017 (an actual MTU stall)? The dev box has no host firewall rules, and an MTU stall needs a size probe. Both need a lab VM with ufw or firewalld rules, or a tunnel with a reduced MTU. (Resolve before v0.2.)
10. How do we reproduce WR023 (`network_mode: host` on Docker Desktop means the VM)? It needs Docker Desktop, so it's tested in M7's manual lab runs. (Resolve in M7.)
