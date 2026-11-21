# whyreach — INITIAL.md

> **What this is:** the build brief for whyreach's first release: the decisions that came out of the critique, the HLD, the LLD, MVP scope, and the test plan.
> Where this file and the original project proposal (not published) disagree, this file wins. The proposal stays as background and rationale.
> **Name:** the project was renamed from NetDoctor to **whyreach** on 2026-11-13 because of a trademark conflict (§10 Q5). The original proposal keeps the old name.
>
> **Status:** M0 to M5 done (all 14 v0.1 rules, the MCP server, policy and `doctor`; an agent diagnoses every lab scenario through MCP alone; as root, container checks enter the containers' network namespaces with no Docker write; outside names and private addresses need the user's approval (§10 Q11, Q13–Q15); reports, a demo and release builds prepared locally; the agent benchmark, re-run so that no agent could see its scenario's name: whyreach's agent clearly better than a shell-only one on 18 of 21 scenarios, §6.4); v0.1.0 released on 2026-11-14 (archives, image, MCP Registry), and the README shows the demo and the benchmark; next: the launch post, the owner's step (draft in `docs/launch/`). **M6 (v0.2) in progress:** WSL2 is built (platform classification, Docker Desktop's PIDs kept out of `/proc` and `setns`, the host's side labelled the WSL2 VM; ADR 0004), passed the owner's manual lab runs on Windows (2026-11-21, `docs/wsl2-lab.md`) and is claimed for v0.2; the six v0.2 rules follow in ADR 0002's order, WR015, WR024, WR014, WR013 and WR016 built 2026-11-21; then CI mode · **Updated:** 2026-11-21
> **Dev box:** Ubuntu 24.04.5, kernel 7.0, Go 1.27.0 (builds use the `toolchain go1.27.4` pinned in `go.mod`), Docker Engine 29.9.3 (API 1.56), Compose v5.7.1

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

**Result (M1, 2026-11-13):** all four pass in `make lab` (`test/lab/healthy`, `wr007-localhost`, `wr004-separate-projects`, `wr002-loopback-bind`), plus `wr008-not-running`. Each runs twice: with probe containers on, and with the default config (tier 2b off). WR007, WR004, WR002 and WR008 reach high confidence in both; the healthy control is `no_problem_reproduced` with probes and `inconclusive` without them, because nothing can confirm reachability. A diagnosis took 10–20 ms without probes, about 200 ms with a probe container, and about 2.2 s for WR004, whose probe waits out the 2 s connect timeout to api's address.

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
| **probe-container** (default) | Create a tiny container with `NetworkMode: container:<target>`, run the whyreach probe in it, read its stdout, remove it | Docker API only | ✅ | ✅ (later) | imports the labeled probe image once per build; creates, starts and removes 1 labeled container | ~0.5–2 s |
| **netns** (fast path) | `setns()` into `/proc/<pid>/ns/net` on a locked OS thread | root or `CAP_SYS_ADMIN` | ✅ | ❌ (Linux Engine only) | none | ms |
| `docker exec` | Run `ss` or `nslookup` inside the target | Docker API | ❌ (the tools are missing) | ✅ | an exec | ~0.3 s |

**Decision:** implement `probe-container` first and `netns` second (selected automatically when running as root; built in M3, ADR 0001's M3 amendment). Never use `docker exec`.

Why probe-container is the right default:
- A container started with `--network container:X` shares X's network namespace. Docker also gives it **X's own `/etc/resolv.conf` and `/etc/hosts`**, so the probe's DNS view matches the app's exactly: the embedded DNS at 127.0.0.11, `extra_hosts`, and aliases. *(Verified in M0, ADR 0001.)*
- Reading `/proc/net/tcp` and `/proc/net/tcp6` from inside the probe lists X's sockets. That checks the bind address without root and without any tools inside X.
- No registry pull is needed. On Linux, whyreach imports its own static binary as a `FROM scratch` image named `whyreach-probe:<version>-<digest>`, where `<digest>` is the first 12 hex digits of the binary's SHA-256. The digest keeps development builds, which share a version string, from running a stale probe. Before importing, whyreach checks that the daemon runs Linux on the same architecture and that the binary is a static ELF. When whyreach itself runs as a container, it reuses its own image.
  - whyreach never deletes images (the probe allowlist has no image delete), so every new build leaves one ~11 MB image behind. Remove old ones with `docker image prune -a --filter label=io.whyreach.probe=1`.
- The probe is hardened: `CapDrop: ALL`, `ReadonlyRootfs`, `User: 65534`, `no-new-privileges`, no mounts, no environment, a pids limit and a memory limit, the label `io.whyreach.probe=1`, and a hard timeout. The probe client builds this config itself; callers can't change it.
- It does **not** use AutoRemove: the daemon deletes an auto-removed container, logs included, as soon as it exits, before whyreach can read its output (ADR 0001, amendment). whyreach removes each probe itself after reading the logs, and at startup sweeps labeled leftovers from a crash. The sweep only removes stopped probes older than two minutes, so it never touches a probe that a concurrent whyreach process is still using, and a failed sweep is retried by the next run. A create request interrupted by a cancel or the deadline may still create the container, so the executor then removes any container with exactly that name and the probe label.

**Trade-off:** importing the probe image and creating a container are Docker writes. Both are therefore **tier 2b** (§4.9): off unless the user enables them in config, or approves through MCP elicitation where the client supports it. Every result reports them in `side_effects` (for example: `"ephemeral probe container wr-probe-3f2a9c1d (removed)"`, plus `"imported image whyreach-probe:0.1.0-1f679e8cdc7a"` on first use). `changes_made` stays `false`.

**Verified in M0 (ADR 0001):** the probe container works exactly as described above, hardened and without a registry pull.
- **Listeners from the host:** on Linux Docker Engine, the destination's listeners can also be read from the host through `/proc/<pid>/net/tcp{,6}`. This needs no root and no Docker write, once `/proc/<pid>/cgroup` confirms that the PID belongs to the container.
- **Without tier 2b:** v0.1 can still conclude most of its rules. The rule experiments (`docs/research/rule-experiments.md`) show that, of the v0.1 rules, only WR020 depends on the probe container. WR005 and WR011 just lose their DNS confirmation.
- **Still needs the probe container or root:** WR020, WR014 and WR016; WR021 and WR022, which weren't reproduced but are marked Probe? "yes" in §4.6; and confirming reachability from the source.

### 3.4 Main flow: `diagnose_connection(from=container:worker, to=api:8080)`

1. **Parse and guard.** Turn the arguments into typed endpoints. Policy checks the permission tier and the shape of the target.
2. **Resolve entities.** Find `worker` through Docker, and the container whose network namespace it uses (itself, or X for `network_mode: container:X`).
3. **Collect (in parallel).** List the containers. Inspect every container whose name or Compose service is `api` (up to 16), and up to 64 other containers on worker's networks (the list has no aliases); skipped containers and failed inspects become gaps, so incomplete metadata is never read as "no such container". Then match `api` against container names, Compose services, aliases and DNSNames, unless worker's own `extra_hosts` map `api`, which `/etc/hosts` answers before any DNS. Read api's listening sockets from the host through `/proc/<pid>/net/tcp{,6}` (§3.3). For a `localhost` target, also read worker's, its network peers' and the host's listeners (WR007 needs them to choose its fix).
4. **Gate.** Check container state before any probe: nothing is probed from a stopped source, or when every container the name refers to on the source's networks is stopped (WR008's case; it has no address and can't be joined). A stopped match outside the source's networks doesn't stop the probes: the name may mean something else.
5. **Probe from worker's namespace.** Look up `api` (`/etc/hosts` first, then DNS for A and AAAA). Try a TCP connect to each resolved address (at most 4, 2 s each). When api sits on a network worker isn't on, also connect to api's own addresses from Docker metadata (at most 2): the timeout shows the path is blocked too, and it never counts as reaching the target.
6. **Evaluate.** Run every rule whose required evidence exists. Evidence that couldn't be collected becomes a gap.
7. **Compose.** Rank the findings, choose a verdict, and attach facts, `next_checks` and `side_effects`. Then render for MCP or the CLI.

### 3.5 Deployment modes

| Mode | How it runs | Sees the host's netns? | Container checks | Notes |
|---|---|---|---|---|
| Native (default) | `whyreach mcp serve` / `whyreach diagnose …` | ✅ | ✅ via probe-container | Linux only |
| Native as root | `sudo whyreach diagnose …` | ✅ | ✅ via the netns fast path, no Docker writes (M3; a probe container stands in only when entering fails and tier 2b is on) | for CLI use; avoid as an MCP server (`mcp serve` warns when it runs as root) |
| As a container | `docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/sandstrompl/whyreach:<version> mcp serve` | ✅ with `--network host`; without it, host-side checks are unsupported records and gaps, never the container's own state passed off as the host's (M4). whyreach asks Docker about its own container, found from the files Docker mounts over `/etc` (`/proc/self/mountinfo`); only without Docker's answer does a Docker bridge in sight (`docker0`, `br-<id>`) decide | ✅ via `/proc/<pid>/net` with `--pid host` (Docker's PID for whyreach's container is then in its `/proc`); without it, containers' listeners are unsupported records with the advice, and listener-based causes drop a level. Also via probe-container | zero-install; the route to macOS and Windows (v0.3+). M4: the image is `FROM scratch` with the release binary, nothing pulled; config at `/config/whyreach/config.toml` (mount yours), audit log under `/state`, reports under `/data` (`Dockerfile`) |
| Inside WSL2 (Windows) | the MCP client on Windows launches it with `wsl.exe -d <distro> --exec /abs/path/whyreach mcp serve` (§3.7, item 6) | describes the WSL2 VM, not Windows (labelled so in every fact) | `wsl2-engine`: as on Linux (listeners through `/proc/<pid>`, probe containers, the netns fast path as root). `wsl2-desktop`: only via probe-container, through the socket that Docker Desktop's WSL integration provides (WSL 2 backend and Linux-containers mode only), listeners included | v0.2; the Linux build runs unchanged. Built in M6 (ADR 0004), claimed once the manual lab runs pass |

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

**As built in M6, Phase 1 (2026-11-14; ADR 0004; the owner's manual lab runs on Windows passed on 2026-11-21, `docs/wsl2-lab.md`, so it is claimed for v0.2):**
- **Classification** (`platform.Classify`): from where whyreach runs (`platform.Detect`: WSL2 needs a `microsoft` kernel, WSL's interop entry, `WSLInterop` or `WSLInterop-late`, and no container) and the daemon's `GET /version` (Docker Desktop names itself). Recorded as a `platform` evidence record in every diagnosis; rules read it from the view.
- **Docker's PIDs** are this machine's only on `linux-engine` and `wsl2-engine` (`platform.EngineHere`). Elsewhere, Docker Desktop's WSL integration included, the engine reads no `/proc/<pid>` and never uses the netns executor, even as root: containers' listening sockets are read in probe containers joined to them (at most 6 a diagnosis, the source and the destinations first), and without probe containers the record is unsupported with advice, which makes an MCP client's user be asked for them.
- **The host's side under WSL2** is labelled the WSL2 VM in records, facts, gaps and rule prose. On `wsl2-desktop` the host a container reaches is Windows (or Docker Desktop's VM for `network_mode: host`): its listeners are an unsupported record and a gap with how to check on Windows, never the VM's sockets. WR011 fires only on Docker Engine; WR012 never concludes from the VM's state there.
- **`doctor`** names the platform, warns on `wsl2-engine` that WSL stops idle distros (and `dockerd` with them), and prints the `wsl.exe` command in WSL2. **Launching:** `--log-level` joins `WHYREACH_LOG` (a Windows client's environment doesn't reach WSL), and a test runs the real binary and requires `mcp serve` to exit within 3 s of its input ending (it takes milliseconds).

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
│   ├── labserver/          the lab's distroless stand-in service (serve, check)
│   └── e2e/                harness that runs the lab (build tag: lab)
├── docs/
│   ├── adr/                architecture decision records (0001-execution-contexts.md, …)
│   ├── research/           background research (failure-signatures.md)
│   └── rules/WR001.md …    one page per rule (pitfall, evidence, fix), ShellCheck-wiki style;
│                           embedded in the binary for `whyreach rules explain` (package docs/rules, M4)
├── demo/compose.yaml       the README's demo (WR007); also the lab scenario test/lab/demo-localhost (M4)
├── spikes/                 M0 throwaway spikes; not product code (ADR 0001)
├── Makefile · go.mod · .golangci.yml · .goreleaser.yaml · Dockerfile · server.json (MCP Registry)
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
// Status says whether a check produced an observation, not what it observed:
// a refused connect is StatusOK with Outcome "refused".
type Status string // ok | failed | timeout | unsupported | permission_denied | skipped | error

type ContextRef struct {
    Kind      string // "host" | "container"
    Container string // short id; empty for host
    Name      string // display name: the Compose service ("worker") or the container name
    NetnsID   uint64 // netns inode, when readable: proves two checks ran in the same place
    Executor  string // "host" | "probe-container" | "netns"; empty for metadata and host-read data
}

type Evidence struct {
    ID          string        // "ev-07": assigned after collection in a canonical order, so the
                              // same evidence gets the same IDs whichever collector finished first
    Kind        Kind          // docker.version, docker.container, netns.listeners, probe.dns, probe.tcp,
                              // host.addrs (M2); docker.network, host.route arrive with the v0.2 rules
    Context     ContextRef
    Subject     string        // "api:8080", "container:shop-api-1", "listeners"
    Status      Status
    ObservedAt  time.Time
    Duration    time.Duration
    Data        any           // typed payload per Kind (below); JSON-decoded by Kind
    Err         *EvidenceErr  // {Code, Message, Errno}
    Limitations []string
    Source      string        // "docker GET /containers/{id}/json", "/proc/<pid>/net/tcp{,6} read from the host"
}

type TCPProbe  struct { Target string; Addr netip.AddrPort; Via /* literal|hosts|dns|metadata */ string
                        Outcome /* connected|refused|timeout|unreachable|reset|closed|blocked|error */ string; Errno string; RTT time.Duration }
type DNSProbe  struct { Name, Answered /* "api" or "api.<search 1>" */, Via /* hosts|dns */, Server string
                        Rcode /* NOERROR|NXDOMAIN|SERVFAIL|REFUSED|TIMEOUT */ string; Answers []netip.Addr
                        Upstream []string /* Docker's ExtServers comment */; Attempts []DNSAttempt }
type Listeners struct { Sockets []Socket } // Proto ("tcp" | "tcp6"), Local netip.AddrPort; LISTEN only
type Container struct {
    ID, Name, Image, State, Health string
    ExitCode, Pid, RestartCount   int
    StartedAt, FinishedAt         time.Time
    Compose      *ComposeRef     // project, service (from labels; no other label is kept)
    NetworkMode  string          // bridge | host | none | container:<id> | <network>
    Networks     []NetAttachment // network, IPv4, IPv6, gateway, Names (aliases ∪ DNSNames), Internal (M2: from the network list)
    Ports        []PortMap       // container port/proto → host ip:port
    ExtraHosts   []string
}

// ---- diagnosis ----
type Diagnosis struct {
    Verdict       string       // cause_identified | likely_cause | inconclusive | no_problem_reproduced
    Summary       string       // one sentence
    ID            string
    SchemaVersion int          // 1
    Question      Question     // from (with the resolved container ID) and to (host, port, class)
    Findings      []Finding    // primary first, then "also found" in fix order
    Suppressed    []Suppressed // findings another finding's rule supersedes, with By
    Facts         []Fact       // {Text, Evidence []string}
    Gaps          []Gap        // {What, Why (permission|unsupported|timeout|failed|error|policy), Detail, HowToEnable, Evidence}
    NextChecks    []NextCheck  // {Why, Tool, Args}: machine-actionable
    SideEffects   []string     // e.g. ephemeral probe containers
    ChangesMade   bool         // always false
    Timing        Timing
    Evidence      []Evidence
}

type Finding struct {
    RuleID        string   // "WR002"
    Title         string
    Layer         Layer    // §4.5
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
  - The source's `extra_hosts` come first: `/etc/hosts` answers before any DNS, so a mapped name refers only to a container holding that address (or, for `host-gateway`, to the host).
  - An address, given literally or through `extra_hosts`, refers to the container that holds it, running or paused. Only when none does, it refers to a container that isn't running but has it as its fixed address (Compose `ipv4_address` or `ipv6_address`): Docker keeps that in the endpoint's `IPAMConfig` while the container is stopped, and shows it as a created container's address too, so WR008 names the container rather than WR024 calling the address stale. A container that is up comes first because Docker hands a stopped container's fixed address to other containers (measured on Engine 29.9.3; the stopped one then fails to start with "Address already in use"). A dynamic address is cleared when its container stops, and nothing records it (M6).
  - Docker's DNS answers names only on user-defined networks: the default `bridge` answers nothing, so a container there matches by name but resolves nowhere.
  - A match that shares no network of any kind with the source (the default bridge counts) is WR004's evidence. Matches are ordered with the source's own Compose project first, then by container name.
  - `service:<name>` without a project is an error when the service exists in several Compose projects; the message lists them.
- **Classes:** the target is a `name`, an `ip`, or `loopback` (`localhost`, `*.localhost`, `ip6-localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`).
- **Rejected:** CIDRs, address and port ranges (`10.0.0.1-5`, `api:8080-8090`), port lists, wildcards, other schemes, URLs that contain credentials, IPv6 zones, and literal addresses that the probe policy blocks (§4.9). Rejections exit with code 3.

### 4.4 Engine

The engine is a staged pipeline per workflow, not a generic DAG engine (YAGNI): **resolve → collect → gate → probe → evaluate → compose** (see §3.4). The gate checks container state before any probe (WR008). When only the source's own lookup shows that the target is the host (a name that resolves to a host address, or from the host to loopback, like the machine's own hostname), the host's side is collected right after the probes (M2).

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
  1. The TCP connect from the source succeeded, through the name or literal address the app uses → `no_problem_reproduced`, with next checks for app-level, TLS or timing problems. A connect to an address taken from Docker metadata doesn't count. Neither does a connection the peer accepts and closes within 100 ms without sending a byte (outcome `closed`, M2): docker-proxy does exactly that when the published container's port refuses, so counting it would report a dead service as reachable. Any findings that remain, such as advisories, are listed as "also found". The exception is a target that means several addresses, of which the app's own client picks one: when the source connected through one and was refused through another, and the primary finding explains the refusal at medium or higher, the verdict follows the finding, and the summary names both addresses (M6). Only WR014 does so: `localhost` means `127.0.0.1` and `::1`, the listener takes one family, and whether the app fails depends on which address its client tries and whether it falls back.
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
- Findings that only follow from another are dropped through `Supersedes()`. This applies whichever finding does the superseding, primary or not (WR002 drops WR001 even when WR004 is primary), and the dropped findings stay visible in the diagnosis's `suppressed` list.
- Independent findings in later layers stay, listed as "also found" in fix order. Example: "after you connect the networks, api still only listens on loopback".
- `rules.Rank` implements this: it sorts by layer, then confidence, then the rule's evaluation order.

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
| WR013 | WR016, WR024 | The host's route sends the traffic into Docker's bridge (measured in M6). WR024 only with a route of a VPN's or a LAN's that covers the address too: it shows the address is meant to be a machine there, not a container's old one. |
| WR010 | WR001, WR003 | A server that is still starting listens on nothing, or not yet on its final port (M2). |
| WR019 | WR001 | Nothing on the host listens because the container's port isn't published there (M2). |
| WR006 | WR012 | The loopback "host service" is the container's port published on 127.0.0.1 (M2). |
| WR011, WR009 | WR005, WR016 | The name can't resolve for a reason these explain (M2). |
| WR005 | WR016 | — (M2) |
| WR012, WR003 | WR001 | — (M2) |

### 4.6 Rule catalog

Sources for the columns:
- **Rank:** real-world frequency, from `docs/research/failure-signatures.md`.
- **Probe?** whether the rule needs the probe container, from `docs/research/rule-experiments.md`.
- **Release:** the build order decided in ADR 0002.

**v0.1 is 14 rules:** WR001–WR012, WR019 and WR020. All 14 are built (M1: WR008, WR007, WR004, WR002; M2: the rest), each with fixtures, a lab scenario and a page in `docs/rules/`.

**v0.2 adds six,** in ADR 0002's order: WR015, WR024, WR014, WR013, WR016, WR021. Built so far: WR015, WR024, WR014, WR013 and WR016 (M6, 2026-11-21; ADR 0002's M6 amendments), WR024 without its second half.

| ID | Pitfall | Layer | Key evidence | Probe? | Rank | Release |
|---|---|---|---|---|---|---|
| WR001 | Nothing is listening on the port in the destination's netns | 5 | listeners (no match) + refused | no | — | v0.1 · **M2** |
| WR002 | Service bound to loopback only (127.0.0.1 or ::1) | 5 | loopback-only listeners | no | 11 | v0.1 · **M1** |
| WR003 | Service listens on a different port (suggest that port) | 5 | listeners | no | — | v0.1 · **M2** |
| WR004 | The two containers share no network (e.g. separate Compose projects) | 3 | network membership, Compose project labels | no | 2 | v0.1 · **M1** |
| WR005 | The name matches no container, service or alias on the source's networks (suggest the closest), or is an alias only on a network the source doesn't share. Decided from metadata, **not** from the DNS rcode | 3 | network members (+ DNS view) | partly | 8 | v0.1 · **M2** |
| WR006 | The host-published port is used between containers, or a port published only on the host's loopback is reached from a container through the host's address | 2 | port mappings + target | no | 17 | v0.1 · **M2** |
| WR007 | `localhost`/127.0.0.1 (or a name `extra_hosts` map to loopback, or that resolves to loopback) used inside a container to reach another container or the host. The fix differs: the service name, or `host.docker.internal` | 2 | target + source listeners + other containers' and host listeners | no | **1** | v0.1 · **M1** |
| WR008 | The destination is not running, is restarting, or is unhealthy. Checked before any probe | 1 | state, health, RestartCount | no | not measured | v0.1 · **M1** (moved from M2: the engine's gate needs it) |
| WR009 | Default `bridge` network: containers can't resolve each other's names | 3 | network name (`bridge`) | no | 12 | v0.1 · **M2** |
| WR010 | Startup race: the destination isn't ready yet | 1 | health `starting`, StartedAt, listeners | no | 4 | v0.1 · **M2** |
| WR011 | `host.docker.internal` doesn't resolve on Docker Engine (no `host-gateway` mapping). Never fires on Docker Desktop | 2 | ExtraHosts + platform (+ DNS) | partly | 7 | v0.1 · **M2** |
| WR012 | A host service is bound to 127.0.0.1, so containers can't reach it (Linux Engine, and WSL2 without Desktop) | 5 | host listeners + target is the host | no | 5 | v0.1 · **M2** |
| WR013 | A Docker subnet overlaps a VPN or LAN route: the host (or a container, through the host or on that network) sends traffic for a machine there into Docker's bridge. High when a route that isn't Docker's covers the address too, medium without one. Not built: a VPN route more specific than a Docker subnet (host-to-container traffic leaves the bridge), and a VPN client's routes inside a container | 4 | host route lookup (the route the kernel picks and the routes that cover the address) + network subnets and bridges | no | 15 | v0.2 · **M6** |
| WR014 | IPv6/IPv4 mismatch on loopback: `localhost` means `::1` as well as `127.0.0.1` (Docker's `/etc/hosts` in every container, and many hosts'), but the listener is IPv4-only; or the converse, a server on `::1` or on an IPv6-only `[::]` and a client on `127.0.0.1`. When the target means both addresses and one works, whether the app fails depends on its client (medium) | 5 | the source's lookup + listener families + a connect to each address | yes | 18 | v0.2 · **M6** |
| WR015 | `internal: true` network, but the target is outside it: the host, an address on none of the source's subnets, or a name with a dot that no container answers to. A target on the source's subnets is never outside: the host stays reachable through the network's own gateway address | 4 | the networks' internal flags and subnets + the target (+ ENETUNREACH from the source) | no | not measured | v0.2 · **M6** |
| WR016 | Timeout means a silent drop: every connect through the target's name or address timed out, with no accept, refusal or ICMP error. High when the network the containers share disables inter-container communication (`enable_icc=false`); medium when the destination (a container on a shared network, or the host) would have answered; low otherwise (an address outside Docker, the host connecting to a container, a listener whose accept queue holds connections). Last resort: suppressed when WR004, WR005, WR008, WR009, WR011, WR013, WR015 or WR024 explains the timeout, and WR021 once built. Never EHOSTUNREACH or ENETUNREACH, which are answers | 4 | TCP timeout + the destination's listeners (with their accept queue) + the shared network's `enable_icc` + for an address outside Docker the host's route | yes | not measured | v0.2 · **M6** |
| WR017 | MTU mismatch. Advisory until a size probe confirms a stall | 6 | link MTUs | no | 16 | v0.3 |
| WR018 | Proxy env vars intercept traffic. Reads env var **keys only**, never values | 6 | env keys | no | not measured | v0.3 |
| WR019 | Port not published, published under another host port or on another host address, or a container name used from the host's network namespace (host → container) | 2 | actual port bindings + container listeners, and for a target on the host the host's listeners or a refused connect from the host (M4) | no | 6 | v0.1 · **M2** |
| WR020 | The container's upstream DNS fails: internal names resolve, external ones time out | 3 | DNS from the source + `resolv.conf` `ExtServers` | yes | 3 | v0.1 · **M2** |
| WR021 | The host firewall rejects container-to-host traffic (EHOSTUNREACH to the host) | 4 | errno + host listener (+ firewall rules, needs root) | yes | 9 | v0.2 |
| WR022 | No outbound NAT or forwarding | 4 | `ip_forward`, daemon firewall settings | yes | 10 | v0.3 |
| WR023 | Docker Desktop: `network_mode: host` means the VM | 2 | platform + NetworkMode | no | 14 | v0.3 · M7 |
| WR024 | Stale or hard-coded container IP: an address on one of the source's networks (given literally or through `extra_hosts`) that no container holds, other than the network's gateway. Not built yet, the second half: the source's sockets still pointing at an old IP (an app that looked a name up once), which needs the source's connection table | 2 | the source's subnets and gateways + the containers' addresses (+ no answer from the source: EHOSTUNREACH, or whyreach's 2 s timeout before ARP gives up at about 3 s); for the second half, the source's socket table | partly | 13 | v0.2 · **M6** (first half) |
| WR025 | Advertised-address redirect (Kafka and similar) | — | — | — | 19 | deferred (ID reserved) |
| WR026 | A network disables inter-container communication: `enable_icc=false`, or the daemon's `"icc": false` for the default bridge | 4 | Docker's network options, from metadata alone | no | not measured | planned, after v0.2's six rules (not in v0.2); until then WR016's high case (ADR 0002's M6 amendments) |

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
  1. Make sure the image `whyreach-probe:<version>-<digest>` exists (§3.3). If it doesn't, import the binary's own executable as a scratch image (`POST /images/create?fromSrc=-`, setting `ENTRYPOINT ["/whyreach", "__probe"]` and the label `io.whyreach.probe=1` through `changes`), and report the import in `side_effects`. First check that the daemon's OS and architecture (from `/version`) match and that the binary is a static ELF.
  2. Create the container with the hardened config from §3.3 (no AutoRemove), start it, and wait for it under the timeout (`wait?condition=not-running`).
  3. Read the logs: stdout is one JSON evidence object per line. Without a TTY the log stream is **multiplexed with 8-byte frame headers**, so demux it.
  4. Remove the container (`DELETE …?force=1`). This runs on every path, timeouts and cancellation included, under its own short context, so a cancelled diagnosis still cleans up.

  There is one container per (diagnosis, context), and all specs for that context run in it as a batch.
- **`netns`**:
  - Used only on `linux-engine` and `wsl2-engine` (§3.7). First verify that the PID belongs to the target container, for example by checking that `/proc/<pid>/cgroup` contains the container ID. On Docker Desktop, `State.Pid` is a PID in another namespace and can match an unrelated local process, so a blind `setns` could enter the wrong namespace.
  - Call `runtime.LockOSThread()`, open `/proc/<pid>/ns/net`, and call `unix.Setns(fd, CLONE_NEWNET)`. Create the sockets there; a socket keeps the netns it was created in.
  - Restore the original netns before unlocking. If the restore fails, never unlock; Go then terminates the thread.
  - The mount namespace is **not** switched, so read the container's resolver config through `/proc/<pid>/root/etc/{resolv.conf,hosts}`.
- **Probe mode:** the same binary has a hidden `whyreach __probe --spec '<json>'` subcommand. The spec is a JSON list of at most 8 checks (`{"kind":"dns"|"tcp"|"listeners","host":…,"port":…,"via":"metadata"}`), each validated against the target grammar and policy. It writes one evidence record per line, finishes within 6 s (under the container's 8 s), and exits non-zero only on an internal error.
- **Which netns a probe joins:** the source's netns owner (the source itself, or X for `network_mode: container:X`); the evidence is reported in the source's context.
- **Time:** the executor passes the probe a budget (`--budget`) of what is left of the diagnosis minus the container's own overhead, at most 6 s, so a late probe stage still returns what it found.
- **Side effects** are collected per diagnosis (through its context), so a long-lived process never reports one diagnosis's Docker writes in another.

**As built in M1:** the `host` and `probecontainer` executors. The executor stamps every record with its context and executor; a batch that can't run at all still returns one record per check, with the failure status, so the gap names the exact checks.

**As built in M2:** the engine gets its executors wrapped by `policy` (§4.9). The probe allowlist reaches the probe through the context: the host executor applies it in-process, and the probe container receives it as `__probe --allow <prefixes>`, so it holds at dial time for every address a name resolves to. `ProbeContainer.Readiness` checks the daemon's platform, the binary and whether the image is imported, without any write, for `doctor`.

**As built in M3:** the `netns` executor (`internal/executor/netns_linux.go`; elsewhere a stub answers `unsupported`). ADR 0001's M3 amendment records the decisions.
- **Selection:** as root (`CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` in the initial user namespace), not inside a container, with `openat2` available (Linux 5.6+), and unless `[permissions] netns = false`, the CLI gives the policy a netns executor. The engine uses it in place of probe containers whenever the daemon is a Linux Docker Engine on this host (`linux-engine`, `wsl2-engine`), whatever tier 2b says, for diagnoses and `run_probe` alike (`run_probe` from a host-network container now goes the same way, since that container's resolver files are its own).
- **Entering:** it inspects the container again for its current PID, checks `/proc/<pid>/cgroup` for the full ID, opens `/proc/<pid>/ns/net` and `/proc/<pid>/root`, checks the cgroup again, and enters once with a no-op to prove the privilege. A stopped container gives one record per check with that status. When it can't enter (the PID check fails, as when Docker's PIDs aren't this machine's, or a privilege is missing), a probe container runs the batch if tier 2b is in effect, and the records say so; otherwise they become a gap that says how to let one run.
- **Sockets:** the probes run concurrently, so the probe package takes an `Enter` hook: each DNS query, each TCP connect and the listener read run on a fresh goroutine locked to its thread, which enters the namespace for that one operation and goes back before it is unlocked (if it can't, it stays locked and Go ends the thread). The main thread never enters, since `/proc/self` describes it for every reader; host-side reads go through `/proc/thread-self`. Listeners come from `/proc/thread-self/net/tcp{,6}` inside the namespace.
- **Resolver files:** the container's `/etc/hosts` and `/etc/resolv.conf` are read with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` relative to its root, so no symlink leads to the host's files. Only regular files of at most 16 MiB are read, not on procfs, sysfs or another pseudo file system whose reads have side effects or block; a batch reads each file once, and each lookup waits at most 2 s for it. A hosts file that exists but can't be read fails the lookup.
- **Evidence:** `executor: "netns"` and `netns_id` (the namespace's inode); the same limits as the other executors (§4.9); `side_effects` stays empty, unless a probe container stood in.
- **Known limitation:** a source with `network_mode: container:X` is probed from X's namespace with X's files, as a probe container joins X; a source that bind-mounts its own `/etc/hosts` would differ.

**As built in M6 (ADR 0004):** the engine decides from the `platform` record whether Docker's PIDs are this machine's (`linux-engine`, `wsl2-engine`). Elsewhere (Docker Desktop, its WSL integration included) it never picks the netns executor and never reads a container's `/proc/<pid>`: a container's listening sockets come from a probe container joined to it, as ADR 0001 verified for Docker Desktop, at most 6 per diagnosis (source and destinations first; the rest are skipped records and one gap), each a probe token. The cgroup check stays as a second line of defence.

### 4.8 Collectors and probes

- **`collect/host`** uses `vishvananda/netlink` for links, addresses, `RouteGet(dst)` and neighbours. It reads listeners from `/proc/net/{tcp,tcp6,udp,udp6}`, where addr:port is hex and state `0A` means LISTEN. It never shells out to `ip` or `ss`.
  - **As built in M2:** only what the v0.1 flows need. The host's interfaces and addresses (`host.addrs`) come from the standard library's `net.Interfaces`, which asks the kernel over netlink on Linux and builds on every OS; loopback and IPv6 link-local addresses are left out. Route lookups arrived with WR013 (M6), on the standard library's and `golang.org/x/sys`'s netlink support rather than `vishvananda/netlink`: two requests, RTM_GETROUTE with `RTM_F_FIB_MATCH` for the table entry the kernel picks for one address (as `ip route get fibmatch`), and a route dump of which only the unicast routes covering that address are kept (`host.route`; prefix, interface and table only). They run for a target address in a Docker bridge network's subnet that no container holds (WR013), and since WR016 (M6) for an address outside every Docker network's subnet that the source's connect timed out on, keeping the chosen route even when it is the default one (at most 2 lookups in all); only where Docker Engine runs here. On Docker Desktop the record is unsupported, with advice (§3.7), and WR016 looks nothing up there. WR024 (M6) needed no neighbour table: Docker's metadata shows that no container holds the address, and the source's connect that nothing answers there. TCP listeners come from `probe.ReadListeners("/proc")`; since WR016 each listening socket also records its accept queue's length (`rx_queue`, as `queued` when not 0): a full queue makes the kernel drop new connections, a timeout like a firewall's. Docker's network list also gives each attachment its network's `com.docker.network.bridge.enable_icc=false` (WR016), next to the internal flag, subnets and gateways.
  - **Host targets (M2):** the target is the host's network namespace when it is `localhost` from the host (or a host-network container), one of the host's addresses, a name the source's `extra_hosts` map to `host-gateway`, `host.docker.internal`, or a name that resolved to a host address (collected after the probes, since only the lookup shows it). The engine then reads the host's listeners and the containers that publish the port there; a binding that covers the target address makes that container a destination on its container port. From the host, when nothing answers the port and nothing publishes it, it reads the listeners of up to 32 running containers to find the one that serves it unpublished (WR019).
- **`collect/docker`** uses `net/http` over the unix socket:
  - A `RoundTripper` holds an **allowlist of method + path pattern**. "GET-only" alone isn't enough: `GET /containers/{id}/export` dumps an entire filesystem.
  - Default allowlist: `GET /version`, `/containers/json`, `/containers/{id}/json`, `/networks`, `/networks/{id}`.
  - The probe client is constructed separately with its own allowlist: create, start, wait, logs and delete for containers, plus image inspect and import. It also has `GET /containers/json`, for the startup sweep of labeled leftovers.
    - Image inspect is limited to `whyreach-probe:*`, and import to `fromSrc=-` with `repo=whyreach-probe`; `fromImage` (a registry pull) is refused.
    - It starts and removes only containers it created in this process, or labeled leftovers older than two minutes that its sweep found.
  - The API version is negotiated through `/version`: the lower of the daemon's and 1.56, refusing daemons older than 1.41.
  - The endpoint is `DOCKER_HOST` (unix sockets only) or `/var/run/docker.sock`. Docker contexts and the other platform defaults come with M7.
  - Responses are decoded into minimal structs that we own; unknown fields are ignored. The inspect struct has no `Config.Env` and keeps only the Compose labels.
  - **No Docker SDK.**
- **`probe/dns`** uses a `miekg/dns` client pointed at the resolver from `resolv.conf`. This gives the real rcode, so NXDOMAIN, SERVFAIL and timeout can be told apart; `net.Resolver` hides that difference. It checks `/etc/hosts` first, as nsswitch's `files dns` order does, and records which path answered. Known limitation: the app's libc (glibc or musl) may order A and AAAA results differently. Measured for `localhost` in M6 (WR014; ADR 0002's amendment): musl puts `::1` first, and so does glibc unless the lookup sets `AI_ADDRCONFIG` and the container has no IPv6 address but loopback; Go's resolver puts `::1` first. whyreach records its answers IPv4 first and connects to each, so no rule assumes the app's order.
  - It applies the search list and `ndots` as `resolv.conf(5)` describes, asks for A and AAAA in parallel, retries a timed-out query once (on the next nameserver if there is one), retries a truncated answer over TCP, and bounds a whole lookup at 4 s.
  - Search domains can identify the user's organisation, so evidence records them only as placeholders (`api.<search 1>`).
- **`probe/tcp`** uses `net.Dialer{Timeout}` and classifies errors with `errors.Is(err, syscall.ECONNREFUSED)` and similar checks. It connects and then closes, and never sends a payload.
  - **From M2** it keeps the connection open up to 100 ms first, reading without writing: a peer that closes it at once (EOF or a reset) is outcome `closed`, not `connected` (§4.4). A server that speaks first, or waits for the client, is `connected`.
  - **Control lookup (M2):** when the target name matches no container, the probe batch also looks up the source's own container name. Docker's DNS answers it without leaving the host, and it shows whether internal names resolve (WR005, WR020).
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
- Blocked by default: `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254` (AWS), `fd20:ce::254` (GCE, on IPv6-only VMs; added 2026-11-14), `100.100.100.200` (cloud metadata and link-local addresses), and any of them inside NAT64's well-known prefix `64:ff9b::/96` (M4).
- An optional allowlist (`loopback`, `rfc1918`, `docker`, or explicit CIDRs) restricts targets further.
- A token bucket allows 30 probes per minute, and a name resolves to at most 4 addresses.
- **Names (decided 2026-11-13, built in M4; §10 Q11):** through MCP, a name with a dot that Docker doesn't resolve itself is looked up only after the user approves that name, or when it falls under a domain in `[probe] names`. The nameservers in a source's `resolv.conf` are checked against the block list.
- **Decided and built 2026-11-14, before v0.1.0 (§10 Q13–Q15; as built below):**
  - The host's own resolver may be asked even at a blocked address, for DNS only.
  - An approval of an outside name covers 3 lookups.
  - Through MCP, a TCP probe to a private address outside loopback, Docker's networks and the host's own addresses needs the user's approval of that address and port, unless an explicit CIDR or address in `allow` covers it.

**As built in M4 (names, §10 Q11):**
- **Where it holds:** in the probe, at the moment of sending, for every executor (in-process, a probe container through `__probe --names`, the netns executor). The hosts file answers first, as for the app; a lookup it doesn't answer whose name is held back sends nothing, and its record is a skipped check with code `policy_denied` (`probe.NameNotApproved`). A connect to the name shares that reason, so the two make one gap, which names the setting.
- **Outside names** (`target.OutsideName`): a name with a dot, other than `localhost`, `*.localhost` (RFC 6761 keeps them local, as for `localhost`) and `host.docker.internal`, `gateway.docker.internal`. Addresses are not names.
- **What the policy lets through**, per batch, for MCP clients only: names Docker's metadata knows (the engine passes a check through the context: from the diagnosis's view, or for `run_probe` from the container list and an inspect of up to 64 containers on the source's networks, read only when the answer matters), names `[probe] names` covers, and names the user approved this session. The CLI restricts nothing.
- **Nameservers:** a nameserver from the source's `resolv.conf` on the block list gets no query, with any executor and any client (since 2026-11-14, unless it is one of the host's own resolvers: as built before v0.1.0, below). A lookup uses the first three, read as glibc and musl read them (any `inet_aton` form, such as `0xa9fea9fe`), and asks them in glibc's order: when the first is blocked, no lookup is made (one through the others would describe a lookup the app doesn't make); when a later one is, the lookup uses only those before it, and when neither of its queries (A, AAAA) gets a reply glibc accepts (only no answer, SERVFAIL, REFUSED or NOTIMP), it is refused, since the app would ask the blocked one next. musl asks every nameserver at once, so a musl app may take its answer from a blocked one, which whyreach can't see (a limitation on the record). They are checked before the name, so the user isn't asked about a name that can't be looked up. `doctor` warns when the host's first nameserver is blocked, or, on a systemd-resolved host, the first of the upstreams Docker gives default-bridge containers.
- **Asking:** at most three questions about names a session, none pre-approving; names qualified with a network (`api.shop_default`) count as known to Docker; `[probe] names` entries need at least two labels.
- **Audit:** a held-back lookup counts as denied, not sent; each answer about a name is an entry of its own (`name_lookup_consent`, with the name).
- **Accepted residual risks** (ADR 0003, M4 amendment; §10 Q13–Q15): a container that rewrites its own `resolv.conf` controls where its free names go; names without a dot are harmless only on networks whose resolver and search domains are the user's; an approved name can be looked up repeatedly for the session (since 2026-11-14, 3 times an approval).

**As built 2026-11-14, before v0.1.0 (§10 Q13–Q15):**
- **The host's own resolvers (Q13):** for every batch, and for every client, the policy reads the nameservers listed in the host's `/etc/resolv.conf` and systemd-resolved's `/run/systemd/resolve/resolv.conf` (read as the C library reads them) and hands them to the executors (`probe.Limits.HostResolvers`; a probe container gets `__probe --host-resolvers`). A nameserver on the block list that is among them is asked like any other, for DNS on port 53; a connect to it stays blocked. The record says so (`host_resolver` in the DNS data names the blocked host resolver whose reply the lookup used, and a limitation names it), and the facts call it the host's own resolver. A blocked one that only the container's `resolv.conf` names stays refused, as in M4; for an IPv6 link-local address the zone must match too, since it names the link.
  - In whyreach's image without `--network host` its own `resolv.conf` isn't the host's, so there is no exception. With `--network host`, the container's `/etc/resolv.conf` is Docker's copy of the host's, but systemd-resolved's list isn't there unless `/run/systemd/resolve` is mounted read-only, so default-bridge containers on a systemd-resolved cloud host stay refused; `doctor` warns and gives the mount.
  - `doctor` reports a blocked host resolver as information (asked, DNS only), and warns only when it can't see the host's resolvers.
- **Approval budgets (Q14):** an approval of a name covers 3 lookups (`probe.ApprovalBudget`). A batch takes one lookup per approved name before it runs, so batches running at once can't overspend, and returns it only when its record proves nothing was sent (the hosts file answered, or the nameservers refused), or the executor never ran; a run that failed once started keeps it. A spent approval is asked about again within the session's question limit; a declined name isn't. `[probe] names` and names Docker knows spend nothing.
- **Private addresses (Q15):** for MCP clients, when `allow` has the `rfc1918` class, an address only that class admits needs the user's approval of that exact address and port.
  - **Free:** Docker's bridge networks, whole (their subnets live inside the host), and on other drivers only the addresses Docker gave the containers running here: a macvlan or ipvlan network's subnet is the physical LAN, whose router and other hosts still need approval (safety review), and an overlay network spans other hosts. Docker's networks are listed for each batch, with or without `docker` in `allow`. Also free: the host's own interface addresses (none in the image without `--network host`), loopback, and explicit addresses and CIDRs in `allow`. Without an allowlist (`allow = []`), or without the `rfc1918` class, nothing is asked: the allowlist decides.
  - **Where it holds:** the guard checks literal targets before sending, and the probe checks every resolved address at dial time (`probe.Limits.CheckConnect`). A batch is given, per approved address and port, at most one connect per TCP check to that port, and never more than the approval has left; the probe counts them down, and what goes unused returns when every connect record either kept its data or was skipped (which sends nothing: a name that didn't resolve, a refusal), and the run didn't fail once started; before the executor runs, everything returns.
  - **Without approval** nothing is sent: the record is a skipped check with code `policy_denied` (`probe.AddrNotApproved`), and its gap names `[probe] allow`. Each answer is audited as `connect_consent`, with the address and port. The CLI is unchanged.

**Hard rule:** tool arguments can only narrow permissions. Tiers come from the user's config or from MCP elicitation, never from the agent.

**As built in M1:** the target grammar rejects everything but one host:port, blocked addresses are refused both when given literally and at dial time (inside the probe too, for every address a name resolves to), and a name resolves to at most 4 addresses. The allowlist option, the token bucket and the audit log arrive with the `policy` package in M2, together with the MCP server whose tool arguments they guard.

**Audit log:** JSON Lines at `$XDG_STATE_HOME/whyreach/audit.jsonl`. Each entry records the tool, its sanitized arguments, duration, status and side effects.

**As built in M2:** the `policy` package is the only way into the engine: the CLI and the MCP server both call it, and only it builds an engine (an import test enforces this).
- It parses every argument with the target grammar, and classifies errors by code (§4.14).
- **Tiers:** 2b comes from `probe_containers` in the config, or from the user's approval of an MCP elicitation, which holds for the session (§4.10). The engine gets guarded executors: while tier 2b is off they answer with permission-denied records, which become a gap that says how to enable it.
- **Allowlist:** an empty `allow` means no allowlist (only the block list). Otherwise TCP probes may go only to the listed classes and CIDRs: literal addresses are refused before sending, and the probe checks every address a name resolves to at dial time. `docker` is the subnets of Docker's networks when the probe runs (since 2026-11-14, of its bridge networks; on other drivers only the addresses of the containers running here: a macvlan or ipvlan network's subnet is the physical network, and an overlay network spans other hosts). A refused check is a record with the reason, so it becomes a `policy` gap with advice. DNS queries go to the source's own resolver and aren't subject to the allowlist.
- **Rate limit:** one token per DNS or TCP check (a TCP check to a name covers its up to 4 addresses); listener reads are free. The bucket holds `rate_per_minute` tokens and refills at that rate, per process.
- **Audit:** every call, including refused ones and consent answers, with the client (`cli` or `mcp`), the verdict and primary rule, the diagnosis ID, whether tier 2b was in effect, and the probes sent and refused. Arguments are stripped of control characters and cut at 256 characters. The file is 0600 in a 0700 directory and rotates once at 10 MB. A failed write is logged, not fatal.

**As built in M3 (tier 3):** whyreach's own privilege turns the netns executor on: root, or precisely `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` in the initial user namespace, outside a container, with `openat2` (`platform.Info.NetnsExecutor`). No tool argument does, and `[permissions] netns = false` keeps it off (narrowing only). The policy wraps it in the same guard as the others: the allowlist (literal addresses before sending, every resolved address at dial time), the block list, and the rate limit (one token per DNS or TCP check; listener reads are free, as from the host). It needs no tier 2b, since it writes nothing to Docker, so no consent is asked for it; when it can't enter a namespace, a probe container stands in only while tier 2b is in effect, and through MCP the user is asked for probe containers, as when a check needs one. `inspect host` shows `netns on (root)` or `off`, and each audit entry records `netns`, whether tier 3 was in effect.

### 4.10 MCP surface (4 tools)

| Tool | Input | Output |
|---|---|---|
| `diagnose_connection` | `to`, `from?`, `expect?` (`connect`) | Diagnosis (compact) |
| `inspect_environment` | `scope`: `host`, `container:<x>`, or `network:<x>` | compact facts (no raw dumps) |
| `run_probe` | `kind` (`dns`, `tcp` or `listeners`), `target`, `from?` | a single Evidence |
| `save_report` | `diagnosis_id` (M2's `redact?` goes in M4: bundles saved through MCP are always redacted, §10 Q12) | path + redaction summary |

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

**As built in M2:** `whyreach mcp serve`, with go-sdk v1.8.0's typed `mcp.AddTool` handlers; ADR 0003 records the decisions.
- **Structured content** is `report.Compact`: verdict, summary and ID first, then findings (only the primary carries its explanation), facts, gaps, next checks and side effects. It is cut to fit 6000 bytes of JSON, about 1.5k tokens, by dropping the least important parts first and saying what was omitted. The text content is the CLI's rendering, of similar size. Goldens cover both.
- `inspect_environment` also takes `service:<name>[@<project>]`. `run_probe` returns every record its one check produced: a TCP check to a name is its lookup plus a connect per address.
- **Probe containers by consent (§10 Q3):** when tier 2b is off and a diagnosis or probe would gain from a probe container (a settled high-confidence cause never asks), the server asks the user once per session, through the client's own elicitation dialog. Clients on protocols before 2026-07-28 get a server-initiated `elicitation/create`; newer ones get an input request in the tool result (SEP-2322) and call again with the answer, which the server accepts only with the request state it issued. An approval turns tier 2b on for the session, is audited, and re-registers the two probing tools with `readOnlyHint: false`. Clients without elicitation get the gap and the config advice.

**As built in M4 (§10 Q11, Q12):** when a diagnosis (not settled at high confidence) or a `run_probe` had an outside name held back, the server asks the user about that exact name through the same two elicitation paths as probe containers, once per name per session, and runs the check again on approval. An approval covers that name only (not its subdomains), for the session; a decline isn't asked again. On the 2026-07-28 path the request state names the question it carries (probe containers, or which name), and an answer counts only for that question. When probe containers are needed too, they are asked about first. `save_report` has no `redact` argument: bundles saved through MCP are always redacted, and a call that passes `redact` fails the input schema. A golden file pins the four tools' schemas and annotations (`internal/mcpserver/testdata/tools.golden`).

**As built 2026-11-14, before v0.1.0 (§10 Q14, Q15):** an approval covers 3 lookups of the name, and a spent one is asked about again. Private addresses outside Docker's networks, loopback and the host's own addresses get the same question per address and port (key `private_connect` on the 2026-07-28 path), on both elicitation paths, with "no" as the default and 3 connects an approval, unless an explicit CIDR or address in `[probe] allow` covers them. Questions about names and addresses share the session's limit of 3; a declined one isn't asked again. The advice a client reads promises a question only when one would be asked.

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

**As built in M1:** the short form, `diagnose` (without `--report`, which arrives with reports in M4) and `version`, plus the hidden `__probe`. Text output goes to stdout, sanitized of control and bidi characters; `--json` prints the full `Diagnosis`, evidence included; logs are JSON on stderr (`WHYREACH_LOG=debug|info|warn`).

**As built in M2:** `inspect`, `probe`, `doctor` and `mcp serve`, all through `policy`; `report` and `rules` remain for M4. **M3:** `doctor` has a `netns executor` line: as root it enters one running container's namespace and reads its `resolv.conf`, sending nothing; otherwise it says why it is off. `mcp serve` warns when it has root's privileges, and every command run as root warns when its state or data directory belongs to another user (`sudo -E`). `--from host` now has its own rules (WR019, and WR001–WR003 through published ports). `doctor` exits 0 when no check failed and 1 otherwise; it checks the config, the Docker API, interfaces, host and container listeners, probe-container readiness (read-only), the probe policy, privileges, whether whyreach runs in a container or WSL2, and the audit log.

**As built in M6 (ADR 0004):** a global `--log-level` flag (debug, info, warn) overrides `WHYREACH_LOG`, since a Windows MCP client's environment doesn't reach WSL. `doctor` has a `platform` line (the setup whyreach found), on `wsl2-engine` a warning that WSL stops idle distros and `dockerd` with them, and in WSL2 the `wsl.exe` command for MCP clients on Windows. `inspect host` reports the platform. `mcp serve` exits as soon as its input ends.

**As built in M4:** `diagnose --report` (and the short form) saves the diagnosis as an unredacted bundle in the data directory and says so on stderr, so `--json` output stays JSON alone. `report list` (newest first, `--json`), `report show <id>` (its `report.md`) and `report export <id> [--redact-private]` (§4.12). `rules list` (`--json`) and `rules explain <id>`, which prints the rule's page from `docs/rules`, embedded in the binary. In a container, `mcp serve` doesn't warn about root (the socket grants access, not root), and `doctor` suggests the `docker run` command.

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
- Routes that aren't Docker's (`host.route`, M6) map the user's other networks: their ranges, their interfaces (unless named by a plain word) and the host's own addresses on those interfaces get pseudonyms (`ip-…`, `if-…`) in every redacted report, whether or not private addresses are kept.

**Never collected:** env var values, file contents other than `resolv.conf` and `hosts`, and packet payloads.

**As built in M2 (for `save_report`):** the four files, under `$XDG_DATA_HOME/whyreach/reports/<diagnosis ID>/` (the ID begins with its UTC time; `-unredacted` is appended without redaction), so saving the same diagnosis again returns the same bundle. Redaction learns values from the structured fields (addresses, DNS names with a dot, aliases, links, registries, container and network IDs) and every address in any string, then replaces whole tokens everywhere, folding ASCII case only so byte offsets hold. The user's home directory becomes `~`. Redacted addresses are no longer addresses, so a redacted bundle decodes as plain JSON, not into whyreach's types. The CLI's `report` commands and `--report` come in M4.

**As built in M4 (CLI):** `--report` saves an unredacted bundle, `<id>-unredacted/`: the user's own record, made by the user (§10 Q12). `report export <id>` writes a redacted copy as `<id>.tar.gz` in the reports directory (the four files under `<id>/`), never outside whyreach's own directories; it prints the path. An unredacted bundle is decoded back into a diagnosis and redacted afresh, under a new key; a bundle saved redacted through MCP is copied as it is, and with `--redact-private` (or `[report] redact_private`) its private addresses are replaced too. `show` and `export` take a diagnosis ID, or a bundle's directory name; both are checked against the ID grammar before any path is built, and an ID saved both ways means the unredacted bundle.

### 4.13 Config

`$XDG_CONFIG_HOME/whyreach/config.toml`

```toml
[permissions]
docker = true
probe_containers = false        # tier 2b
netns = true                    # tier 3: as root, enter containers' namespaces (M3)

[probe]
allow = ["loopback", "rfc1918", "docker"]
rate_per_minute = 30
names = []                      # domains whose names MCP clients may look up without asking (M4, §10 Q11)

[timeouts]
diagnosis = "15s"

[report]
redact_private = false
```

M1 reads `[permissions]` and `[timeouts]` (the deadline must be 3–60 s) and accepts the other documented keys. M3 adds `[permissions] netns` (default true): false keeps the netns executor off even as root. An unknown key is an error, so a typo can't silently leave a permission at its default. A missing file means the defaults: Docker on, probe containers off. M2 also reads `[probe]` (`allow` entries must be a class, a CIDR or an address; `rate_per_minute` must be 1–600) and `[report] redact_private`. M4 adds `[probe] names` (§10 Q11): domains such as `example.com`, each covering its subdomains; entries are folded to lowercase without a trailing dot, and wildcards, addresses and anything that isn't a domain name are errors. It applies to MCP clients only.

### 4.14 Errors and logging

- **Error codes:** `invalid_argument`, `policy_denied`, `docker_unavailable`, `permission_denied`, `not_found`, `timeout`, `unsupported`, `internal`, and `limit` (M2: whyreach's own bound on what it collects was reached, such as the 64 containers it inspects on the source's networks; the record makes the metadata incomplete for the rules, and a gap says what was skipped).
- **Logging:** `log/slog` as JSON, to **stderr only**. In `mcp serve`, stdout carries the protocol, so a stray `fmt.Println` breaks the session.
- **Errors:** wrap them with `%w` and keep the syscall errno; rules depend on it.

### 4.15 Cross-platform build rules

- Files that use netlink, `/proc` or `setns` carry `//go:build linux`. Each such package has an `_other.go` stub that returns `Status: unsupported` with a gap explaining why.
- `probe/tcp` and `probe/dns` are portable; the host executor uses them on every OS. `probe/listeners` is Linux-only. The probe entrypoint (`__probe`) always runs inside a Linux container, and stays cgo-free so it builds statically for amd64 and arm64.
- `make cross` compiles the whole module for darwin and windows (amd64 and arm64). It runs in CI from M0, so portability can't break silently. CI also runs `make vuln` (govulncheck), so a standard-library or dependency advisory in code we call can't go unnoticed either.
- Config, report and audit paths come from one helper: the XDG directories from §4.9 (audit), §4.12 (reports) and §4.13 (config) on Linux, and the platform's standard user directories on macOS and Windows.

---

## 5. EXAMPLES

**CLI (actual M1 output, from `internal/cli/testdata/text-cause.golden`)**

```
$ whyreach diagnose --from container:shop-worker-1 api:8080
✗ worker → api:8080 — cause identified (high)

WR002  api listens only on 127.0.0.1:8080 inside its container
       api's only listener for port 8080 is 127.0.0.1:8080 (in api). A socket
       bound to loopback accepts connections only from inside api's own
       network namespace, so worker can't reach it.
  facts  • worker and api share network shop_default                 [ev-02 ev-03]
         • "api" → 172.22.0.3 via 127.0.0.11:53, in worker           [ev-05]
         • connect 172.22.0.3:8080 from worker: refused, ECONNREFUSED (0.1 ms)  [ev-06]
         • listening on port 8080 in api: 127.0.0.1:8080/tcp         [ev-04]
  fix    Make the server in api listen on 0.0.0.0:8080 (or [::]:8080), for
         example with --host 0.0.0.0 or a HOST=0.0.0.0 setting, then restart
         api.
  docs   docs/rules/WR002.md

side effects: ephemeral probe container wr-probe-3f2a9c1d (removed)
changes made: none
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
description: api listens only on 127.0.0.1:8080 inside its container
from: service:worker@${PROJECT}   # the harness substitutes the unique project name
to: api:8080
expect:                           # with probe containers on
  verdict: cause_identified
  top_rule: WR002
  confidence: high
  must_not_fire: [WR004, WR005, WR007, WR008]
  tcp_outcomes: ["dns:refused"]   # some TCP probe, via the name, was refused
expect_without_probe:             # with the default config (tier 2b off)
  verdict: cause_identified
  top_rule: WR002
  confidence: high
```

Other keys: `projects` (compose files; `compose.<x>.yaml` runs as project `<base>-<x>`), `up_wait: false` with `settle: {service, state}` for scenarios where `up --wait` would fail, and the expectations `fix_contains` and `side_effects_max`.

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
They cover the text, Markdown and MCP-text renderers, and the MCP `structuredContent` JSON, which is what agents actually read (ADR 0001). Regenerate the golden files with `make golden`. Since M2 the text renderer, the compact structured form and the `Diagnosis` JSON live in `internal/report` (`testdata/*.golden`), shared by the CLI and the MCP server; `internal/mcpserver` tests the tools over in-memory transports.

### 6.3 Lab (integration)
- **Layout:** each scenario is `test/lab/<scenario>/`, containing `compose.yaml` and `scenario.yaml`.
- **Harness** (build tag `lab`, `test/e2e`):
  1. build whyreach and the lab's stand-in server (`test/labserver`, a static binary imported FROM scratch as `whyreach-lab-server:<digest>`; nothing is pulled)
  2. `docker compose -p whyreach-lab-<name>-<rand> up -d --wait`
  3. run the real binary with `--json`, once with probe containers on and once with the default config
  4. assert on the result and the exit code
  5. `down -v`, then check that no probe container was left behind and remove the run's images
- Unique project names keep scenarios away from every other container. The scenarios still run one at a time: they reuse service names (`api`, `worker`), and a diagnosis looks at every container on the host, so parallel scenarios would see each other's `api`.
- **Starting point:** the experiment scenarios: E1–E6 and E8 are Compose files in `spikes/experiments/`, and E7 and E9 run inline in `spikes/experiments.sh`. M1 promoted the slice scenarios first (ADR 0002), plus `wr008-not-running`. Note that `up --wait` would hang on the slow-start and crash-loop scenarios, so those need their own wait conditions (`up_wait: false` and `settle`).
- **netns variants** need root: `make lab-root` (M3) builds whyreach, the lab server and the test binaries as the user, then runs only the test binaries with `sudo`: the executor's root-only tests (a socket made through `Enter` lives in the other namespace, every thread is back home afterwards, and the main thread never enters while concurrent `/proc/self` reads stay home; these also run without sudo in a user namespace, with loopback up: `unshare -Urn sh -c 'ip link set lo up && …'`), and `TestLabNetns` (build tags `lab,privileged`). That runs every scenario as root, with probe containers off and on: each must reach its `expect` (the with-probe expectations), with empty `side_effects`; every DNS and TCP check from a container must have run through the netns executor in the source's namespace (its inode, read through the source's PID); `whyreach probe tcp` from each container source must go the same way; and over the whole run, `docker events` must show no probe container and the build's probe image must never appear. As root, `TestLab` skips itself, since its default-config expectations assume no probes.
- **CI** runs on GitHub Actions Ubuntu runners, which have Docker and sudo.
- **v0.1 scenario set:**
  - one scenario per MVP rule
  - the healthy control
  - two scenarios that must stay inconclusive, e.g. listeners unreadable plus a timeout
- **As built in M2:** 20 scenarios, all passing with probe containers on and with the default config in about 40 s: one per v0.1 rule, plus two more for WR019 from the M2 review (`wr019-random-port`, a port Docker picked; `wr019-ipv6-only`, a port published on `::` alone); `healthy` and `healthy-host-published` (the host reaching a container through docker-proxy); and two that must stay inconclusive, `inconclusive-stale-ip` (a connect to an address on the network that no container holds, WR024's case in v0.2) and `inconclusive-app-closes` (a server that accepts and closes every connection). Listeners can't be made unreadable on the dev box without root, so the second pair differs from the example above. The harness fills in `${LAB_PORT}` (a free host port, also given to Compose), `${HOST_PORT}` (with `host_listen: [loopback|docker0]`, a listener on the host) and `${UNUSED_IP}`.
- **Inside WSL2 (M6, ADR 0004):** the harness classifies its platform as whyreach does and prints it. Where Docker's PIDs aren't this machine's (`wsl2-desktop`), every scenario's `expect` must still hold with probe containers on (the listeners come from probe containers, and every listener read must have come from one), and the default config, which can't look inside containers, must degrade honestly: the expected cause or a weaker verdict, never another cause, the expected rule at no higher confidence, and, when weaker, a gap that says how to allow probe containers (`expect_desktop_without_probe` overrides that for `wr019-not-published`, where WR001 at medium is the honest answer). `expect_on: {<platform>: {verdict_in, must_not_fire}}` replaces both expectations where a scenario's premise doesn't hold: WR011's and WR012's scenarios on `wsl2-desktop`. `host_listen: docker0` stays on loopback where Docker's bridges aren't this machine's. The runs are manual, on the owner's Windows PC, once per setup: `docs/wsl2-lab.md` and `test/wsl2/run-lab.sh`, plus `test/wsl2/mcp-launch.ps1` for the launch from Windows. On the dev box, `make lab-desktop` rehearses `wsl2-desktop`'s run: whyreach reaches Docker through a proxy whose `GET /version` says Docker Desktop, and classifies the dev box `linux-desktop`, so the Windows host's record, the WSL2 VM's labels and the WSL2 fact are covered by unit tests only, until the owner's run. All 21 scenarios and `TestLabPrivateAddresses` pass that way (2026-11-14); its first run found that the host's search for an unpublished server dropped containers whose sockets it couldn't read, so WR001 claimed "nothing listens" at high confidence (fixed: one record and a gap, and WR001 at medium).
- **v0.2 rules (M6):** a scenario per rule as it is built. 26 scenarios now, and `make lab` and `make lab-desktop` pass them all; `make lab-agent` and `make lab-bench` haven't run the six below yet.
  - `wr015-internal-network` (2026-11-21): a client only on an internal network reaches for a host service through `host.docker.internal`, while the host listens where `host-gateway` points. WR015 is primary at high with probe containers on and with the default config, and the same under `make lab-desktop` (nothing platform-specific).
  - `wr024-stale-ip` (2026-11-21): worker connects to an address on its network that no container holds. WR024 is primary at high with probe containers on (the connect times out) and at medium with the default config, and the same under `make lab-desktop`. It is the scenario that was `inconclusive-stale-ip`, renamed rather than given new expectations under its old name: the benchmark's records (`docs/research/agent-benchmark/`) keep that name with the answer that was right then, `none`, so the two questions stay apart.
  - `wr014-localhost-ipv6` (2026-11-21): app shares proxy's network namespace (`network_mode: service:proxy`), proxy listens on `127.0.0.1:7100` alone, and app connects to `localhost:7100`. With probe containers on, the connect to `127.0.0.1` works and the one to `[::1]` is refused: WR014 is primary at medium and the verdict likely_cause (§4.4), the same under `make lab-desktop`. With the default config WR014 isn't evaluated (Probe? yes): inconclusive, with the gap. Its first run under `make lab-desktop` without probe containers, where no listener can be read, found WR007 guessing at medium that `localhost` meant app alone; WR007 no longer guesses for a source in another container's network namespace.
  - `wr013-subnet-overlap` (2026-11-21): the host connects to an address in the project network's subnet that no container holds, standing in for a machine on a VPN or LAN whose range Docker's network took. The host's routing table sends it into the network's bridge: WR013 is primary at medium, with probe containers on and with the default config alike (the route lookup needs no probe, and from the host the connect runs in-process). Under `make lab-desktop` the route record is a gap and the diagnosis inconclusive (`expect_on`). The high case, with a VPN's route, can't be built without changing the host's routes: fixtures, an engine test and the route lookup's test against made-up routes in an unprivileged network namespace cover it.
  - `wr016-silent-drop` (2026-11-21): worker and api share the project's network, whose bridge has inter-container communication disabled (`com.docker.network.bridge.enable_icc: "false"`), so Docker drops the traffic between them: worker's connect to api times out although api listens. The only drop the lab can make without pulling an image or changing the host, and it stays on this machine. With probe containers on, WR016 is primary at high (the network's option names the dropper, the timeout confirms it); with the default config WR016 isn't evaluated (Probe? yes): inconclusive, with the gap; the same under `make lab-desktop`, where traffic between containers stays in Docker Desktop's VM. The medium and low cases, a drop whyreach can't name, need a firewall rule: fixtures and engine tests cover them, after measurements in a network namespace. The harness's new `suppressed` expectation checks that WR016 appears only as suppressed in `wr024-stale-ip` (by WR024) and `wr013-subnet-overlap` (by WR013, on the first run: the second starts while ARP for the address is under way, and may get "no route to host" before whyreach's timeout).
  - `inconclusive-outside-allowlist` (2026-11-21) takes its place as the second scenario that must stay inconclusive. worker connects to 198.51.100.7, a documentation address standing in for a service outside Docker and outside this machine. The probe allowlist (loopback, RFC 1918, Docker's networks) keeps whyreach from connecting to it, so nothing is sent and no probe container runs, and the gap says how to allow it (`[probe] allow`); with probe containers off, the gap says how to allow them. Why this case: the policy decides it, not the network, so it is deterministic and the same under `make lab-desktop`; it sends nothing; and none of the v0.2 rules to come can explain it. WR016 needs a timeout, which the policy never lets happen; WR013 and WR021 need a target on a Docker subnet or the host; WR014 needs a loopback target. The example above, unreadable listeners plus a timeout, can't be built without root, and a timeout will be WR016's.
  - Both scenarios that must stay inconclusive now expect no finding at all, suppressed ones included (`no_findings` in `scenario.yaml`), so that a rule built later can't claim either unnoticed.
- **The demo (M4):** `test/lab/demo-localhost` runs `demo/compose.yaml` (its `compose.yaml` links to it) with the same expectations as WR007's scenario. Its `image:` key names the public image it runs (`python:3.13-slim`): the scenario is skipped where that image isn't present, so the lab still pulls nothing.
- **Agent check (`make lab-agent`, M2's exit criterion):** for each scenario, a headless Claude Code on a small model (`claude -p --model haiku`, `--tools ""` so only whyreach's four tools exist) gets a one-line problem report and must name the rule the lab expects, or none. It runs with probe containers on in the config, since a headless run can't answer a consent request, and with `[probe] names = ["example.com"]` for WR020's scenario (M4).
  - **No hints (since 2026-11-14, as in §6.4):** the agent sees the scenario only as a developer would.
    - The scenario runs as a Compose project with a neutral name (`whyreach-lab-<6 hex>`), from copies of its Compose files without comments.
    - Every directory the agent works in sits under a fresh `whyreach-agent-*` directory, whyreach's XDG directories included (whyreach's advice names its config file). `t.TempDir()` would name a subtest's directory after its scenario.
    - The answer format names no rule ID.
    - Claude Code runs clean: `--setting-sources project,local`, `--strict-mcp-config`, `--disable-slash-commands`, no CLAUDE.md files, memory or updates, and a minimal environment.
  - **The check:** before each agent starts, the test checks what it hands the agent: the prompt without its target (the target is the problem itself), the arguments, the environment, the project name, the directories and the MCP configuration. None may contain a rule ID, the scenario's name or one of its words (`bench.Hints`). `TestScenariosGiveNoHints` (`test/bench`, in `make test`) checks every scenario's problem report and Compose copies the same way.
  - **Before that,** the project name and the directory names named the scenario, the prompt's example answer was WR002's, and the owner's Claude Code configuration loaded into every run (plugins with their hooks, CLAUDE.md files, memory). M2's and M4's `make lab-agent` results came from that setup.
  - **The client, checked:** each agent's init event, Claude Code's own record of what it loaded, must show only the tools it was given, whyreach's server (connected) or none, Claude Code's built-in plugins and no skill, slash command, output style or added directory (`checkClean`).
  - **Result (2026-11-14, two runs on Claude Haiku):** 21 of 21 both times, through whyreach's tools alone, with 1 to 8 tool calls (median 2, then 1), about 150 s of agent time and $0.019 a run (M4's run, with the owner's configuration loaded, cost $0.031). The new-user check passed both times: the install took 9 and 12 turns, and each diagnosis one `diagnose_connection` call that named WR007.
- **New-user check (`TestAgentNewUser`, in `make lab-agent`; M4's exit criterion):** a fresh headless agent gets only the README and a release-layout archive with `checksums.txt` (goreleaser's `dist/` with `WHYREACH_RELEASE_DIR`, otherwise one the test builds with the same flags and layout), in a temporary directory that stands in for its home. It verifies, installs, writes the MCP configuration and starts the demo; a second fresh agent with only whyreach's four tools diagnoses it, and must answer WR007. The test checks that the installed binary and the demo the agent ran are the archive's, and that nothing landed in the real home. Since 2026-11-14 the demo runs as a neutral project (`whyreach-lab-<6 hex>`, until then `whyreach-lab-demo`), both agents run with the clean client in a fresh `whyreach-agent-*` directory, and the second starts in an empty directory after the agent check's check for hints (under the demo's lab name, `demo-localhost`). The first agent may read the sandbox, write only the MCP configuration, and run the few commands the README's steps need, with Compose only as the README starts and reads the demo under the test's project name. That keeps an honest agent in its sandbox; it is no boundary against a hostile checkout, since the agent follows the repository's README with the user's Docker access and, like every `make` target, the test runs the repository's own code. The lab targets are for a checkout you trust.

### 6.4 Agent benchmark (the validation experiment)
For each lab scenario, run a headless agent twice:
- **(a)** with shell only
- **(b)** with whyreach's MCP tools only, no shell

Record whether it found the right root cause, how many tool calls and tokens it used, the wall-clock time, and any unsafe commands it attempted. If (b) isn't clearly better on at least half the scenarios, narrow the scope before v1.0. Publish the results table; it doubles as the launch post.

**As built in M5 (`make lab-bench`, 2026-11-14).** The method was fixed and committed before the first run: `docs/research/agent-benchmark.md`.
- **The arms:** headless Claude Code on Claude Haiku, with (a) its `Bash` tool only or (b) whyreach's four tools only, and the same prompt: the problem report, "only investigate", and the 14 v0.1 pitfalls as a list to choose from, ending with a `RESULT:` line. Both run with a clean client (none of the owner's settings, plugins, hooks, CLAUDE.md files or memory), at most 40 turns, $0.50 and 8 minutes, on a fresh copy of the scenario under a neutral Compose project name (`make lab`'s names contain the scenario's), with its Compose files copied without comments, in a run directory whose name says nothing about the scenario. Before each agent starts, the harness checks that nothing it hands the agent names the scenario or its cause (the directory names and the check came after the first run; see the result below).
- **The same boundary for both:** neither writes to Docker. whyreach runs with its default config (probe containers off; headless Claude Code cancels the consent request), so it can't confirm a working connection or diagnose WR020; the shell's Docker access is read-only.
- **Judging:** right means the `RESULT:` line names the scenario's `expect.top_rule`, or `none` for the healthy and inconclusive scenarios. **Unsafe** means privilege, a Docker write (`docker exec` included), a change to the host, or probing beyond one target. **Clearly better:** right where the other arm is wrong, or both right with at most half the tool calls and half the cost, or both right while only the other attempted something unsafe.
- **Containing the shell agent** (it runs on the owner's machine): every command, and the guard hook, runs through `CLAUDE_CODE_SHELL_PREFIX` inside `bwrap`: a read-only file system except its own sandbox, `/home` and other private places hidden, its own PID namespace, no capabilities or new privileges, and a seccomp filter that refuses Unix sockets, `io_uring` and the kernel key rings (`test/benchguard`). Docker is reached only through a proxy on the host's loopback that shows only the lab and refuses every write (`test/bench`). A `PreToolUse` hook parses each command and denies, with the reason, the unsafe kinds; denials, refused Docker writes and writes the sandbox stopped count as unsafe attempts, once per command. The harness checks the sandbox before any agent runs, and that every command ran inside it.
- **Privacy:** results and transcripts are masked before they're written (user and host names, e-mail, DNS servers and search domains, interface names, other Docker projects, MAC addresses and addresses outside the lab), and a last check refuses to write anything that still shows one.

**Result (2026-11-14, the second run; `docs/research/agent-benchmark.md`, raw data in `docs/research/agent-benchmark/`): §6.4 passed.** One run per arm and scenario on `claude-haiku-5-5`: 42 runs, $0.083. They came from two invocations: 40 runs in 10.3 minutes, then `wr004-separate-projects`' two in 25 s. Those two were re-run with the owner's approval after the new hint check stopped them before their agents started: a false alarm on the harness's folder name.
- **Accuracy:** each agent named the right cause in 20 of 21 scenarios. The shell agent took a loopback-only server on another port for WR002 on `wr001-nothing-listening`; whyreach's agent answered `none` on WR020's scenario.
- **Effort:** whyreach's agent used a median of 2 tool calls against the shell agent's 6, 12.5k tokens against 38.9k, and 6.5 s against 16.6 s, at about 40% of the cost.
- **Safety:** the shell agent attempted 18 unsafe commands in 18 of its 21 runs, all `docker exec`, diagnostic in intent and denied by the guard; whyreach's agent attempted none.
- **Clearly better:** whyreach's agent on 18 scenarios (14 on calls and cost alone, 3 more on safety, and 1 where only it was right), the shell agent on 1 (WR020, where only it was right). Without the safety condition, 15. The bar is 11, so the scope isn't narrowed.
- **WR020:** without probe containers whyreach was inconclusive there, as expected, and its agent didn't name a cause it couldn't confirm. The shell agent read the dead DNS server from the Compose file and confirmed it with `dig`.
- **Caveats:** the catalog and the lab's stand-in servers, whose command lines show their listen addresses, made both arms' job easy; one model, one run each.
- **The first run** (the same day) leaked: its agents could see their scenario's name in their directory names. A shell agent's working directory is in its system prompt, and whyreach's advice prints its config path. So the benchmark was run again with only the directory names changed, plus the check. The first run's results: both agents right on 21 of 21, whyreach's agent clearly better on 18 and the shell agent on none, with medians of 2 against 5 tool calls. That run also had a harness incident: its sandbox check failed once on a matching error, since Claude Code wraps a command that redirects its own input differently. It was fixed. The method doc's "Incidents" has the details.

---

## 7. Milestones

| M | Scope | Exit criterion |
|---|---|---|
| **M0** (≤1 wk) | `git init` and scaffold (Makefile, CI, lint, and a `make cross` compile check for macOS and Windows). Spikes: (1) the privilege matrix; (2) a probe-container proof: `resolv.conf`/`hosts` sharing, `/proc/net` in a shared netns, importing a scratch image; (3) an MCP Go SDK hello-world tool with structured output, called from Claude Code. Collect the top ~20 real failure signatures. | Spike results written up in `docs/adr/0001-execution-contexts.md`. ✅ Done 2026-11-13 |
| **M1** (2–3 wk) | Evidence types, the allowlisted Docker client, the probe-container executor, probes, listeners read from the host (the containers' through `/proc/<pid>`, plus the host's own, which WR007 needs to choose its fix), rule layers and precedence, the slice rules WR007/WR004/WR002 plus the healthy control (ADR 0002), and WR008, which the engine checks before any probe; CLI `diagnose` | The §2.3 vertical slice passes in the lab. ✅ Done 2026-11-13 |
| **M2** (2 wk) | MCP server (4 tools), policy, audit log, host↔container flows (`--from host`, and containers reaching host services) with the host collectors they need, the rest of the v0.1 rules in ADR 0002's order (WR020, WR010, WR012, WR019, WR011, WR005, WR009, WR006, WR003, WR001; WR008 moved to M1), `doctor` | An agent diagnoses every MVP lab scenario through MCP alone. ✅ Done 2026-11-13: `make lab-agent` passed 20 of 20 scenarios on Claude Haiku through whyreach's four tools alone, with 1 to 6 tool calls each (most need 1 or 2), 186 s and about $0.03 in all (§6.3). Re-run on 2026-11-14 with neutral names and directories and a clean client, so that nothing the agent was given named the scenario (§6.3): 21 of 21, twice |
| **M3** (1–2 wk) | netns executor (root) | The same lab passes with the netns executor and no Docker writes. ✅ Done 2026-11-13: `make lab-root` passed all 20 scenarios as root, with probe containers off and on, plus `whyreach probe` from each of the 16 container sources, in 48 s: 82 checks ran inside the containers' own network namespaces, with empty `side_effects`, no probe container in `docker events` and no probe image. Most diagnoses took 13–40 ms, against about 200 ms with a probe container. Two independent reviews (safety and diagnostic correctness) found 13 problems (one by both), among them the main thread entering a namespace and a container's resolver files pointed at procfs, and 7 more when they re-checked the fixes; all were fixed except three left as documented limitations (ADR 0001's M3 amendment) |
| **M4** (1–2 wk) | The §10 Q11 and Q12 decisions (outside names need approval through MCP, nameservers checked against the block list, `save_report` always redacted), reports and redaction, `docs/rules/*`, goreleaser builds (linux amd64/arm64), checksums and attestations, a container image, MCP Registry listing | A new user installs, connects a client, and diagnoses the demo using only the docs. ✅ Done 2026-11-14: a fresh headless agent (Claude Haiku) given only the README and a release-layout archive with `checksums.txt` verified the checksum, installed whyreach, wrote the MCP configuration and started the demo; a second fresh agent with only whyreach's four tools diagnosed it as WR007 in one call (`TestAgentNewUser`, in `make lab-agent`; §6.3). `make lab` passes 21 scenarios (the demo added) with probe containers off and on, and `make lab-agent` 21 of 21. `make lab-root`, run by the owner on `f0f473e`, passed too: all 21 scenarios through the netns executor with probe containers off and on, plus `run_probe` from each container source, in 54 s, with 91 checks run inside the containers' own network namespaces and nothing root-owned or left behind afterwards. Two independent reviews (safety and diagnostic correctness) found 14 problems (one by both); their re-check found 14 more items (9 new, two of them by both, and 5 fixes that were incomplete), checking the image on real Docker 3 more, and a last check of the fixes 3 small ones and 2 gaps in the new-user test. All were fixed, except the residual risks accepted in ADR 0003's M4 amendment and three questions for the owner (§10 Q13–Q15). The release is prepared, not published: goreleaser wasn't run here (`make release-check` and `make release-snapshot` are the owner's first steps), and the tag, the image and the MCP Registry listing are the owner's. §10 Q13–Q15 were then built before v0.1.0 (2026-11-14; §4.9 and §4.10 as built): `make lab` passes the 21 scenarios plus `TestLabPrivateAddresses`, `make lab-agent` 21 of 21, and `make lab-root`, run by the owner on `5c15ef7`, again passed all 21 scenarios through the netns executor with probe containers off and on, plus `run_probe` from each container source, in 54 s, with 91 checks run inside the containers' own network namespaces and nothing root-owned or left behind afterwards. Before the tag, `make release-check` and `make release-snapshot` passed on `d2d6624`: goreleaser v2.19.0 validated `.goreleaser.yaml` and built both static archives with `checksums.txt`, each holding the binary (that commit, go1.27.4), `LICENSE`, `README.md` and the demo, under the names the README's install steps download. The image (skipped by `release-snapshot`) and the release workflow first run on a tag; the workflow's five SHA-pinned actions match the tags they name. `TestAgentNewUser` passed again on 2026-11-14, twice, with a neutral project name and a clean client, its diagnosing agent started in an empty directory (§6.3) |
| **M5** | Benchmark (§6.4) and launch | Results published. ✅ Benchmark done 2026-11-14: `make lab-bench` ran both arms over all 21 scenarios on Claude Haiku. The first run's agents could see their scenario's name in their directory names, so it was run again with only that fixed (§6.4). In the second run each agent was right on 20 of 21, and whyreach's agent was clearly better on 18, the shell agent on 1 (§6.4 passes): a median of 2 tool calls against 6, a third of the tokens, 40% of the time and cost, and no unsafe command, against the shell agent's 18 `docker exec` attempts (all denied). The method was committed before the first run; results, table and masked transcripts are in `docs/research/`. The README's results section is published, with a benchmark chart and a demo GIF (`docs/assets/`, each made by a script there); the launch post is a draft in `docs/launch/`, and posting it is the owner's step |
| **M6** (v0.2) | Windows via WSL2 (`wsl2-desktop` and `wsl2-engine`): platform detection and platform-aware rules (WR011 must not fire under Docker Desktop), host evidence labelled as the WSL2 VM, setup docs for launching through `wsl.exe` (§3.7). CI mode: an example GitHub Actions step that runs `whyreach diagnose --from <source> <target> --json` when Compose tests fail (JSON output and exit codes already ship in v0.1). The v0.2 rules: WR015, WR024, WR014, WR013, WR016, WR021 | The lab passes inside WSL2 in a manual run; the CI example diagnoses a deliberately broken Compose test. **In progress.** Phase 1, WSL2, built 2026-11-14 (ADR 0004; §3.7 as built): `make lab` passes on the dev box, and `make lab-desktop`, its rehearsal of Docker Desktop, passes all 21 scenarios. The owner's manual runs inside WSL2 (`docs/wsl2-lab.md`) passed on 2026-11-21 under both setups, after two fixes (ADR 0004's amendments), so the WSL2 half of this row's exit criterion is met; they run again with the new rules' scenarios before the tag. Phase 2, the six rules in this order: WR015, WR024, WR014, WR013 and WR016 built 2026-11-21 (ADR 0002's M6 amendments; WR024 without its second half, the source's socket table; WR014 in both directions on loopback; WR013 in one direction, a Docker subnet that takes a VPN's or a LAN's range; WR016 for timeouts only, naming the dropper when a network disables inter-container communication; `make lab` and `make lab-desktop` pass their scenarios, 26 in all, `wr024-stale-ip` being the former `inconclusive-stale-ip` and `inconclusive-outside-allowlist` the second scenario that must stay inconclusive; a stopped container's fixed address is WR008's, §4.3); next WR021, then CI mode. Before tagging v0.2: evidence IDs after `docker.version` shift by one (the `platform` record), so regenerate the README's sample output and the demo GIF (`docs/assets/make_demo_gif.py`) |
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
- The DNS rcode for an unknown name depends on the host's resolver, not on Docker. Behind a systemd-resolved stub, single-label names come back SERVFAIL; elsewhere they come back NXDOMAIN; under Docker Desktop on Windows they get no answer within the probe's timeout (WSL2 lab, 2026-11-21). Decide "name not found" from Docker metadata (rule experiments E1, E2), and judge the upstream DNS (WR020) only by names with a dot.
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
3. **Resolved in M2** (ADR 0003): whyreach asks for probe-container consent through whichever path the client supports, and falls back to the config file.

   | Client | Protocol | Elicitation | What happens |
   |---|---|---|---|
   | Claude Code 2.1.323 | 2026-07-28 (no `initialize`; capabilities travel with each request) | declared | the server returns an input request (SEP-2322); headless (`claude -p`) cancels it at once, so the diagnosis carries on without probe containers and the audit log records the answer. The interactive dialog hasn't been tried yet. |
   | Clients before 2026-07-28 that declare elicitation | older | declared | a server-initiated `elicitation/create`, tested with the Go SDK's client |
   | Clients without the capability | any | not declared | never asked; the gap says how to enable probe containers in the config |

   Other clients (Codex, Cursor, VS Code) are untested; the server reads each client's capability, so they need no special handling.
4. **Resolved: import our own binary** (ADR 0001). A 3.3 MB import took 78 ms and an ~18 MB import 69 ms, so Linux needs no registry image. Revisit for M7, when the macOS and Windows builds embed Linux probe binaries.
5. **Resolved: renamed from NetDoctor to whyreach** (2026-11-13). Rule IDs changed from `NDxxx` to `WRxxx` at the same time.
   - **Why the old name had to go** (details in `docs/research/failure-signatures.md`):
     - Riverbed Technology, a network-performance vendor, holds a US trademark "NETDOCTOR" for software (serial 90554897, filed 2021-03-02). Trademarkia and uspto.report list it as registered.
     - A Go network-diagnosis tool for Kubernetes, `kosmos-io/netdoctor`, uses the exact name.
     - The PyPI name was taken.
   - **Why whyreach:** it was free on npm, PyPI, Homebrew core and the MCP Registry, and no GitHub repository used it. No trademark search was done; this is not legal advice.
   - **What wasn't renamed:** the project folder on the dev box is still `NetDoctor/`; rename it outside a running session if wanted. The original proposal keeps the old name as a historical document.
6. **Resolved: Apache-2.0** (`LICENSE` added in M0).
7. Does the probe container work on Docker Desktop with Enhanced Container Isolation turned on (common on business plans)? Docker's docs are silent. Sysbox, which ECI is built on, supports container-to-container network sharing, so it's expected to work, but it must be tested. (Planned for M6, when Docker Desktop's WSL integration is first supported; still open: the owner's Windows PC has no ECI setup, so it moves to M7's Docker Desktop runs.)
8. Which runtimes besides Docker Engine (OrbStack, Colima, Rancher Desktop with moby, Podman) pass the lab unchanged? (Resolve in M7.)
9. How do we test WR021 (host firewall reject) and confirm WR017 (an actual MTU stall)? The dev box has no host firewall rules, and an MTU stall needs a size probe. Both need a lab VM with ufw or firewalld rules, or a tunnel with a reduced MTU. (Resolve before v0.2.)
10. How do we reproduce WR023 (`network_mode: host` on Docker Desktop means the VM)? It needs Docker Desktop, so it's tested in M7's manual lab runs. (Resolve in M7.)
11. **Resolved (2026-11-13, built in M4): through MCP, an outside name is looked up only with the user's approval.** The question (raised by the M2 safety review): the `[probe] allow` list bounds where TCP probes go, but a lookup of any name (`run_probe dns`, or the name in a TCP target) still reached the internet through the resolver. For an agent sandboxed without network access, that made the MCP server, which runs outside the sandbox, a covert channel: a query for `<data>.attacker.example` reaches the attacker's DNS server whatever the answer, one query carries over 100 bytes, and `rate_per_minute` allows 30. Refusing every name Docker doesn't know would close it but break WR020, whose evidence is a timed-out lookup of an outside name; a tighter rate limit wouldn't, since one query is enough. The decision:
    - **Looked up as before:** names Docker resolves itself (containers, Compose services and network aliases, from its metadata), names in the source's hosts file, `localhost`, Docker's fixed names (`host.docker.internal`, `gateway.docker.internal`), and names without a dot, such as a mistyped service name. A query for a name without a dot reaches only the resolver and the servers of the search domains, which the user's own configuration names, never a domain an agent picks; asking for them would cost WR005 its DNS confirmation.
    - **Through MCP, any other name** needs the user's approval of that exact name, asked through the client's elicitation dialog as for probe containers (§4.10) and held for the session, unless it falls under a domain listed in `[probe] names`. Approvals are per name: a yes for one name must not let later names through.
    - **Without an approval** (a client without elicitation, a declined or cancelled request, a headless run) nothing is sent: the record is a policy refusal, and the diagnosis gets a gap that names the setting. Headless runs that diagnose outside names, such as `make lab-agent` for WR020's scenario, list their domains in `[probe] names`.
    - **The CLI is unchanged:** the user types its names, and it runs inside whatever sandbox its caller has.
    - **Nameservers** (raised by the M3 safety review): the nameservers in the source's `resolv.conf`, which the container controls, are checked against the block list (§4.9) for every executor, so `nameserver 169.254.169.254` gets no query.
    - **Built in M4** as decided (§4.9, §4.10). Two choices the decision left open: `*.localhost` counts with `localhost` (RFC 6761 keeps those names local), and an approval doesn't cover subdomains of the approved name.
12. **Resolved (2026-11-13, built in M4): `save_report` loses its `redact` argument.** It was the one argument that relaxed a privacy default: `redact: false` wrote an unredacted bundle whatever `[report] redact_private` said, against non-negotiable 3 ("arguments only narrow"). The risk was small (the bundle stays on the user's machine, and the agent has already seen the diagnosis), but bundles exist to be attached to issues. From M4, bundles saved through MCP are always redacted, and an unredacted one is the user's to make with the CLI's `report` commands. No new setting is needed. **Built in M4:** `diagnose --report` makes the unredacted bundle; `report export` makes redacted copies (§4.12).
13. **Resolved (2026-11-14), to build before v0.1.0 is tagged: the host's own resolver may be asked, even at a blocked address.**
    - **The question** (raised by the M4 correctness review): since M4, whyreach never queries a nameserver on the block list. Some clouds serve DNS at a metadata address: GCE at 169.254.169.254, and at fd20:ce::254 on IPv6-only VMs. So no lookup was made from default-bridge containers, from host-network containers, or from the host where its `resolv.conf` names that resolver directly.
    - **Evidence:** E1 in `docs/research/q13-q15-experiments.md`. By default only GCE and Oracle OCI use such a resolver, and Compose projects are never affected.
    - **The decision:** a nameserver on the block list is asked only when it is one of the host's own resolvers. That means it's listed in the host's `/etc/resolv.conf` or, on a systemd-resolved host, in its upstream list (`/run/systemd/resolve/resolv.conf`).
    - **DNS only:** queries go to it on port 53; TCP probes to it stay blocked.
    - **What that covers:** the resolvers Docker copies from the host (default-bridge and host-network containers) and the host's own lookups.
    - **What stays refused:** a blocked address that only the container's own `resolv.conf` names. A container can't steer whyreach's queries to a metadata address the host doesn't use.
    - **The record** says when the exception applied.
    - **Built 2026-11-14** (§4.9, as built before v0.1.0).
14. **Resolved (2026-11-14), to build before v0.1.0 is tagged: an approval covers 3 lookups.**
    - **The question** (raised by the M4 safety review): an approval held for the session let the agent look the name up again and again. The timing of those queries can carry a few bits a minute to whoever serves the domain.
    - **Evidence:** E2. Every repeated lookup reached the domain's server, through Docker's DNS and directly, whatever the TTL. No agent scenario looked up one name more than 3 times.
    - **The decision:** each approval of an outside name covers 3 lookups in the session. A fourth asks again, within the session's limit of 3 questions; past that limit the lookup is held back with the usual gap.
    - **Names under a domain in `[probe] names`** have no budget.
    - **Built 2026-11-14** (§4.9, §4.10).
15. **Resolved (2026-11-14), to build before v0.1.0 is tagged: through MCP, private addresses outside Docker need approval.**
    - **The question** (raised by the M4 safety review): the default `[probe] allow` lets an agent connect to any private address. The address, port and timing of each connect can carry information to a host on a routed private network.
    - **Evidence:** E3. The lab passes with only `loopback` and `docker` allowed, but a container reaching a published port through the host's LAN address becomes inconclusive. Narrowing the default that way was therefore rejected.
    - **What stays free:** through MCP, TCP probes to loopback, Docker's networks and the host's own interface addresses go as before.
    - **What needs approval:** a probe to an address that only the `rfc1918` class admits. The user approves that exact address and port, asked like Q11's names: the same dialog paths, default "no", the same question limit and Q14's budget of 3 checks.
    - **What skips the question:** an explicit CIDR or address in `[probe] allow` that covers the address.
    - **Without an approval** nothing is sent: the record is a policy refusal, and the gap names the setting.
    - **The CLI** is unchanged.
    - **Built 2026-11-14** (§4.9, §4.10). "The same question limit" is built as one limit shared with names: at most 3 questions about names and addresses together in a session.
