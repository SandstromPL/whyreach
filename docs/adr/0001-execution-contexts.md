# ADR 0001: Execution contexts — where whyreach's checks run

- **Status:** accepted (M0, 2026-11-13)
- **Answers:** `INITIAL.md` §3.3 and §10 Q1, Q2, Q4
- **Evidence from:** the spikes in `spikes/`, run on Ubuntu 24.04.5 with kernel 7.0, Docker Engine 29.9.3 (API 1.56) and Go 1.27.0, as a non-root user in the `docker` group. The MCP check used Claude Code 2.1.323.
- **Re-run:** 2026-11-13, before M1, with the toolchain pinned to go1.27.4. Every DNS, TCP and listener outcome matched the first run, the privilege matrix was unchanged, and the timings were within noise (imports 45 and 72 ms; probe run 630 ms cold, then 129–142 ms).

## Context

To answer "why can't `worker` reach `api:8080`?", whyreach needs three kinds of evidence, each from the right network namespace:

1. **DNS from the source's view:** what `api` resolves to inside `worker`, through Docker's embedded resolver at 127.0.0.11.
2. **A TCP connect from the source's netns.**
3. **The destination's listening sockets,** read inside `api`'s netns.

Usually the containers are distroless, so there are no tools inside them to run. §3.3 proposed three strategies: a probe container, `setns` as root, and `docker exec`. M0 had to prove the default before any product code depends on it.

## Decision

1. **The probe container is the default executor for container-side DNS and TCP probes.** It is a FROM-scratch image of whyreach's own static binary, imported with `docker import` (no registry pull) and run with `--network container:<target>`. It is hardened: `--cap-drop ALL`, `--user 65534:65534`, `--read-only`, `no-new-privileges`, a pids limit, a memory limit, and the label `io.whyreach.probe=1`. Every part of this was verified (below). The spike also used AutoRemove (`--rm`), but the product must not: see the amendment at the end.
2. **New: on Linux Docker Engine, read the destination's listeners from the host** via `/proc/<pid>/net/tcp{,6}`. This needs no root and no Docker write.
   - Before trusting the PID, verify that `/proc/<pid>/cgroup` contains the full container ID. Re-check it after the read to rule out PID reuse.
   - On Docker Desktop, where the PIDs belong to the VM, read the listeners inside the probe container instead (also verified).
3. **The `netns` (`setns`) executor stays root-only** and is scheduled for M3, as planned. A non-root user can't open `/proc/<pid>/ns/net` (verified).
4. **Never `docker exec`.** The distroless target in the spike had no `ss` to run (`executable file not found in $PATH`).
5. **The MCP result's `structuredContent` is the agent's primary view.** Claude Code passed the structured JSON to the model, not the text summary. So the structured output must be compact and self-explanatory on its own (§3.6's token budget applies to it). The text summary stays for other clients.

### What v0.1 can conclude without probe containers (tier 2b off, no root)

On Linux Docker Engine, Docker metadata plus host-read listeners are enough for:
- **WR002 (loopback bind):** if every listener for the port in the destination's netns is on 127.0.0.1/::1, no other netns can reach it.
- **WR001 and WR003:** nothing listening on the port, or listening on a different port.
- **WR004 (no shared network), WR006 (published port used internally) and WR008 (destination not running).**

DNS-view rules (WR005, WR009) and confirming actual reachability from the source still need the probe container or root. Without them, whyreach reports those as gaps (§3.6). *(Refined by ADR 0002: WR005 and WR009 are decided from Docker metadata, so without the probe they lose only the DNS view.)*

## Evidence

### Probe container (`spikes/probecontainer.sh`)

| Question | Result |
|---|---|
| Does a `container:X` probe get X's `/etc/resolv.conf`, `/etc/hosts` and `/etc/hostname`? (Q2) | **Yes.** `docker inspect` shows identical `ResolvConfPath`, `HostsPath` and `HostnamePath`. Markers set only on X (a `--dns-search` domain and an `--add-host` entry) were visible in the probe, whose hostname was X's. |
| Does `/proc/net/tcp{,6}` inside the probe list X's sockets? | **Yes:** `127.0.0.1:8080`, `0.0.0.0:9090` and `[::]:9091`, plus Docker's embedded-DNS listener (see findings). |
| Does it work hardened (uid 65534, `CapEff` 0, read-only rootfs, `no-new-privileges`, pids 32, 32 MB)? | **Yes.** `/proc` reads, DNS via 127.0.0.11, and TCP connects all worked. |
| DNS from the source's view | Network alias → IP ✓, container name → IP ✓, `extra_hosts` entry ✓. A nonexistent name came back NXDOMAIN, from `127.0.0.11:53`. |
| Reproduces WR002? | **Yes.** From worker's netns: `api:8080` refused (loopback-only bind), `api:9090` connected. |
| Reproduces WR014? | **Yes, by accident.** A v6-only `[::]:9091` listener refused an IPv4 connect. |
| Joining a stopped container | The daemon refuses with `cannot join network namespace of a non running container: container … is exited`. That's a clean WR008 signal. |
| Timing (local daemon) | `docker import` of the 3.3 MB binary: **78 ms**; of an ~18 MB tarball: **69 ms**. Image-exists check: **20 ms**. Probe run: **656 ms** cold, then **125–132 ms**. Two probe runs per diagnosis fit easily inside §3.6's p50 < 3 s. |

### What a `docker`-group user can do without root (`spikes/privileges.sh`, Q1)

| Check | Result |
|---|---|
| Read `/proc/<pid>/net/tcp` and `tcp6` of a container process owned by root | **OK.** Decoded the container's listeners from the host. |
| Read `/proc/<pid>/cgroup` | **OK.** It contains `docker-<container-id>.scope`, which makes the PID-identity check possible. |
| `readlink` or `stat` on `/proc/<pid>/ns/net` (netns inode) | denied |
| Read `/proc/<pid>/root/etc/resolv.conf` | denied |
| List `/proc/<pid>/fd` (map a socket to its process) | denied |
| Read `/proc/<pid>/environ` | denied (good) |
| `setns` (nsenter) | denied |
| Host: netlink link dump, route lookup, `/proc/net/tcp` | OK |
| Host: `nft list ruleset`, `iptables -S` | denied (need `CAP_NET_ADMIN`) |
| Docker API `GET` | OK |
| Unprivileged ICMP | disabled (`ping_group_range` = `1 0`) |
| `ss -ltnp` process info | only for the user's own processes (9 of 21 listeners) |

### MCP (`spikes/mcphello/`)

- **Schemas and annotations:** go-sdk v1.8.0's typed handler (`mcp.AddTool[In, Out]`) inferred both the input and output schemas, including the `jsonschema` tag descriptions, and sent the annotations.
- **Results:** `structuredContent` round-trips into the Go type, and our own text summary is kept in `content`.
- **Bad input:** a handler error and a schema-validation failure (wrong type) both come back as tool results with `isError: true`. The model sees them; they are not protocol errors.
- **Claude Code** (headless, `--mcp-config` + `--strict-mcp-config`, a small model, one call):
  - The model received the **`structuredContent` JSON**, not the text summary.
  - Claude Code loaded the tool through its deferred tool search (a `tool_reference` result) before calling it.

## Findings that change the design

1. **Docker's embedded DNS listens inside every container on a user-defined network,** on `127.0.0.11:<random port>` (TCP, plus UDP). Listener-based rules must ignore it, or WR003 would "suggest" a random DNS port.
2. **Go's `LookupNetIP` returns `/etc/hosts` entries as IPv4-mapped IPv6** (`::ffff:10.9.8.7`). Always `Unmap()` addresses before comparing or reporting them.
3. **The container's `resolv.conf` carries the host's DNS search domain and Docker's comments** (`ExtServers: [host(127.0.0.53)]`). The search domain can identify the user's organisation, so report redaction must cover search domains. The comments are useful DNS evidence: they show the upstream servers and whether the host uses a local stub resolver.
4. **The structured result is what the agent reads in Claude Code.** The `Diagnosis` structured output must lead with `verdict` and `summary`, carry short facts plus evidence IDs, and leave raw evidence out (it goes into report bundles).
5. **Clients may defer MCP tools and find them by search.** Tool names and descriptions must contain the words an agent would search for ("network", "connect", "docker", "diagnose").
6. **Host route lookups must go through the kernel** (netlink `RouteGet`), never by reading the `main` table. Machines with VPN clients often route through non-main policy-routing tables; one did so in the spike run.
7. **The MCP SDK pulls in transitive modules for auth features we don't use** (`golang.org/x/oauth2`, `golang-jwt`, a GCP metadata client). Acceptable: only linked code ends up in the binary. Track binary size from M2.

## Consequences

- `INITIAL.md` is updated as follows:
  - §3.3: the listener source, and what works without tier 2b
  - §4.10: structured-first output and tool naming
  - §9: the new gotchas
  - §10: Q1, Q2, Q4 and Q6 resolved
- M1 builds the probe-container executor and the host `/proc/<pid>` listener source first, and `netns` in M3. The spike's `/proc/net` parser (`spikes/internal/procnet`, with tests) can be promoted into `internal/probe`.
- Still open:
  - Q3: which MCP clients support elicitation or input-required results
  - Q7: probe containers under Docker Desktop's Enhanced Container Isolation
  - Q8: alternative runtimes

## Amendment (2026-11-13, before M1): no AutoRemove on the probe container

The M0 spikes ran the probe with `docker run --rm`. The CLI attaches to the output streams before it starts the container, so the output arrives even though the container is auto-removed. The product calls the API instead (create, start, wait, logs, delete; no attach on the allowlist), and there AutoRemove loses the output. `spikes/probelifecycle.sh` checked this on Docker Engine 29.9.3:

| Sequence | Result |
|---|---|
| AutoRemove, then create → start → wait → logs | The logs were gone in 5 of 5 runs: `409 can not get logs from container which is dead or marked for removal` once, then `404 No such container` |
| AutoRemove, following the logs from before start | 0 bytes: the daemon doesn't follow a container that isn't running |
| No AutoRemove: create → start → wait → logs → `DELETE ?force=1` | 699 bytes of multiplexed stdout (frame header 1), then a clean removal |

**Decision:** the probe container doesn't use AutoRemove. The executor removes it after reading the logs, on every path including timeouts and cancellation, and sweeps labeled leftovers at startup. The allowlist stays as it is.

The probe image import is a Docker write too. It is part of tier 2b, carries the label `io.whyreach.probe=1`, and is reported in `side_effects` (`INITIAL.md` §3.3, §4.7).

## Amendment (2026-11-13, M1): the probe image tag carries the binary's digest

M1 names the probe image `whyreach-probe:<version>-<digest>` instead of `whyreach-probe:<version>`, where `<digest>` is the first 12 hex digits of the binary's SHA-256. Development builds share a version string (`dev`, or a `git describe` that ends in `-dirty`), and with the plain tag a rebuilt whyreach would have reused the image of an older build and run a stale probe. The import also checks first that the daemon runs Linux on the same architecture and that the binary is a static ELF, so a dynamically linked build fails with a clear gap instead of a container that can't start.

The cost: every build imports its own ~11 MB image, and whyreach never deletes images (its allowlist has no image delete). `docker image prune -a --filter label=io.whyreach.probe=1` removes the old ones (`INITIAL.md` §3.3).

## Amendment (2026-11-13, M2): a connection closed at once is not "connected"

From the host, a published port is answered by docker-proxy, which accepts the connection and then dials the container. When the container's port refuses (nothing listens, or only on loopback), docker-proxy closes the client's connection at once. A connect-then-close probe saw a completed handshake and reported `connected`, so a host-to-container check through a published port called a dead service reachable.

**Decision:** after connecting, the TCP probe keeps the connection open for up to 100 ms and reads, never writing. A peer that closes it in that time without sending a byte (EOF or a reset) is outcome `closed`, which doesn't count as reaching the service (`INITIAL.md` §4.4). A server that waits for the client, or speaks first, is `connected`. Rules then decide from the listeners behind the published port (WR001, WR002, WR003 check the container port). The lab server now holds connections open like a real server; `serve --close` keeps the old behaviour for `inconclusive-app-closes`.

The cost is up to 100 ms per successful connect; probes run in parallel.

## Amendment (2026-11-13, M3): the netns executor as built

Decision 3 scheduled the `setns` executor for M3. §4.7 fixed the outline (lock the OS thread, `setns` into `/proc/<pid>/ns/net`, restore before unlocking, read the resolver files through `/proc/<pid>/root`); building it settled what the outline left open.

- **One locked thread per socket, not one per batch.** The probes run concurrently (A and AAAA in parallel, one connect per address), and a goroutine doesn't inherit another thread's namespace, so running the batch on one locked thread would have put most sockets in the host's namespace. The probe package now takes an `Enter` hook: every socket a probe creates (each DNS query, each TCP connect) and the listener read are made inside `Enter`, on a fresh goroutine locked to its thread, which enters the namespace, runs one operation and goes back. A socket keeps its namespace, so reads, the 100 ms close check and the close itself run anywhere. The thread is unlocked only once it is back home; if going back fails, it stays locked and Go ends it with the goroutine. A failed `Enter` is recorded as the error it is, never as an rcode or a TCP outcome.
- **The PID is looked up again, and checked twice.** The executor gets only a container reference, so it inspects the container right before entering (an allowlisted GET) for its current PID, then checks `/proc/<pid>/cgroup` for the full ID, opens `/proc/<pid>/ns/net` and `/proc/<pid>/root`, and checks the cgroup again. The descriptors keep pointing at what they opened, whatever the PID does later. It then enters once with a no-op, so a missing privilege shows before any probe depends on it.
- **Resolver files are read inside the container's root, safely.** As root, a symlink in a container must not lead whyreach to the host's files. `/etc/hosts` and `/etc/resolv.conf` are opened with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` relative to the container's root (Linux 5.6 or later; older kernels get an `unsupported` gap), with `O_PATH` first: only a regular file of at most 1 MiB is reopened for reading, so a FIFO or a device is never opened. Listeners are read from `/proc/thread-self/net/tcp{,6}` inside the namespace (`/proc/self` would name the main thread's).
- **Selection.** The privilege is `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE` (opening another user's `/proc/<pid>/ns/net` and `root`) in the initial user namespace, which in practice means root; inside a container whyreach uses probe containers, since Docker's PIDs aren't its own there. The CLI then gives the policy a netns executor, which the policy wraps in the same guard as the others (allowlist, block list, rate limit; no tier 2b, since it writes nothing to Docker), and the engine uses it in place of probe containers whenever the daemon is a Linux Docker Engine on this host, even with `probe_containers = true`. When entering fails (the PID check, a missing privilege), the records say why and become a gap; there is no fallback to probe containers, so a root run never writes to Docker.
- **Evidence.** Records carry `executor: "netns"` and `netns_id`, the inode of the namespace descriptor, as the probe container's do for its own namespace. Sources say the check ran through `setns` and, for DNS, that the files came through `/proc/<pid>/root`.
- **The root lab builds as the user.** `make lab-root` builds whyreach, the lab server and the test binaries as the user, then runs only the test binaries with `sudo`, so nothing root-owned lands in the user's Go caches or home; `TestLabNetns` takes the binaries with `-lab.bin` and `-lab.server`.
