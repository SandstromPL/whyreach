# Rule experiments: what whyreach can observe for each failure

> **How to reproduce:** run `spikes/experiments.sh`. The scenarios are `spikes/experiments/*.yaml`.
> **When and where:** run on 2026-11-13 on Ubuntu 24.04.5 (kernel 7.0) with Docker Engine 29.9.3, as a non-root user in the `docker` group. Re-run the same day before M1, with the toolchain pinned to go1.27.4: every outcome matched.
> **Feeds:** the rule order in `INITIAL.md` §4.5–4.6 and ADR 0002.

## Method

Each scenario reproduces a failure from the frequency ranking in `failure-signatures.md`. The services are distroless stand-ins: the spike probe binary in `serve` mode. Each scenario records what whyreach can see from three vantage points:

1. **Docker metadata** (`docker inspect`).
2. **Listeners read from the host** through `/proc/<pid>/net/tcp{,6}`, without root.
3. **DNS and TCP probes** from a hardened probe container joined to the source container's network namespace.

Rules marked "probe container" need tier 2b (or root, from M3).

## Results

| Exp | Failure (rule) | Result | What the vantage points showed | Needs the probe container? |
|---|---|---|---|---|
| E1 | `localhost` inside a container (WR007) | ✅ reproduced | Probe: `localhost:5432` refused on both `::1` and `127.0.0.1`. Listeners: the source has nothing on 5432, while `db` on the same network listens on `0.0.0.0:5432`, so the fix is `db:5432`. | No. Metadata and listeners are enough; the probe confirms. |
| E1 | Loopback-only bind (WR002) | ✅ | `db:9000` refused; `db` listens on `127.0.0.1:9000` only. | No |
| E1 | Mistyped name (WR005) | ✅, with a surprise | `dbb` failed with **SERVFAIL** ("server misbehaving"), not NXDOMAIN. The network members include `db`, one edit away. | Partly. Metadata shows the name matches nothing; the probe adds the DNS view. |
| E1 | IPv6 `localhost` (WR014) | ✅ signal | Go resolved `localhost` to **`::1` first**, then `127.0.0.1`. `::1` exists inside containers even on IPv4-only networks: the connect was refused, not "cannot assign address". | Yes |
| E2 | Separate Compose projects (WR004) | ✅ | Metadata: different `com.docker.compose.project` labels and disjoint networks. Probe: `api` gives SERVFAIL. Connecting to api's IP directly **timed out** (3 s), because Docker silently drops traffic between networks. | No. Metadata alone is enough. |
| E3 | Upstream DNS unreachable (WR020) | ✅ | The internal name `peer` resolved in 1 ms. `example.com` timed out (≥ 6 s). A TCP connect to 1.1.1.1:443 succeeded. The `resolv.conf` comment `# ExtServers: [192.0.2.53]` names the dead upstream. On the default bridge, `nameserver 192.0.2.53` gave the same timeout. A control container resolved normally. | Yes |
| E4 | Slow start (WR010) | ✅ | Right after start: `health=starting`, no listener, connect refused. Six seconds later: `healthy`, listening on `0.0.0.0:8080`, connected. | No, if the service has a healthcheck. Without one, only uptime and listener evidence. |
| E4 | Crash loop (WR008) | ✅ | `RestartCount` went from 1 to 6, and the status flipped between `running` and `restarting`. It has **no IP while restarting**. Joining its netns fails with "is restarting, wait until the container is running". | No |
| E5 | `host.docker.internal` on Linux Engine (WR011) | ✅ | Without `extra_hosts`: NXDOMAIN. With `host-gateway`: resolves to the docker0 address (172.17.0.1), even from a container on a custom network. | Partly. `ExtraHosts` is enough; the probe confirms the DNS failure. |
| E5 | Host service bound to 127.0.0.1 (WR012) | ✅ | Host listener `127.0.0.1:18432`, read from `/proc/net/tcp` without root. Connecting through `host.docker.internal` was refused, while a listener on the docker0 address accepted. There was no host firewall in the way on this machine. | No |
| E6 | Port not published (WR019) | ✅ | `PortBindings` is empty, a connect from the host to `127.0.0.1:8080` was refused, and the container listens on `0.0.0.0:8080`. | No |
| E6 | Published on loopback only (WR019) | ✅ | Binding `127.0.0.1:18090`. From the host, `127.0.0.1:18090` connected, but the docker0 address was refused. `docker-proxy` shows up as a host listener. | No |
| E6 | Host-published port used between containers (WR006) | ✅ | `weblo:18090` refused, `weblo:8080` connected. Containers on a shared network need no publishing (`web:8080` connected). | No |
| E7 | Default bridge (WR009) | ✅ | Name lookup gave NXDOMAIN: the default bridge has no 127.0.0.11 and uses the host's upstream DNS directly. Connecting by IP worked. | No. The network name is enough. |
| E8 | `internal: true` network (WR015) | ✅ | An external connect fails instantly with "network is unreachable". | No |
| E8 | Black-holed address (WR016) | ✅ | 192.0.2.1:80 timed out. | Yes. This is the weakest signal. |
| E8 | Address on a Docker subnet that no container owns: a stale or hard-coded IP (WR024) | ✅ | "No route to host" (EHOSTUNREACH) after about 3 s of ARP failure, and no container on the network has that IP. | Partly. Metadata is enough; the probe confirms. |
| E9 | Route into a Docker subnet (WR013) | ✅ mechanics | A kernel route lookup for an unused address in a Docker subnet returns the bridge (`br-…`). | No (netlink, no root) |
| E9 | MTU mismatch (WR017) | Signal present | Docker bridges have MTU 1500, and this machine's default egress (a tunnel interface) has MTU 1300. | No. But it stays advisory until a size probe confirms an actual stall. |

**Not reproduced, and why:**
- **WR021, host firewall reject:** this machine has no host firewall rules, and reading nftables needs root.
- **WR022, no NAT or forwarding:** reproducing it means changing the host's sysctl or daemon configuration.
- **WR023, Docker Desktop host networking:** needs Docker Desktop.
- **WR018, proxy env vars:** no proxy on the dev box.
- **WR025, advertised-address redirect:** deferred.

## Findings that change the rules

1. **Don't decide "name not found" from the DNS rcode.** Docker's resolver forwards unknown names to the host's upstream, and the upstream decides the rcode:
   - Behind this host's systemd-resolved stub, unknown single-label names came back SERVFAIL and multi-label names NXDOMAIN.
   - On the default bridge, the LAN resolver answered NXDOMAIN.

   So **WR005 decides from Docker metadata** (the name matches no container, service or alias on the source's networks), and the rcode is only recorded as evidence. **WR020 requires** that internal names resolve while external names time out or fail.
2. **Traffic between networks times out (a silent drop).** Without precedence rules, WR016 would fire on every WR004 case. ADR 0002 handles this with layers.
3. **"Refused" alone proves nothing.** WR001, WR002, WR003, WR006, WR007, WR012 and WR019 all produce ECONNREFUSED; listeners and metadata decide between them. EHOSTUNREACH is ambiguous in the same way (a stale IP versus a firewall reject), and the owner of the target address decides.
4. **Most of the frequent rules need no probe container.** With tier 2b off, v0.1 still covers frequency ranks 1, 2 and 4–7. Only WR020, WR014, WR016, WR005's DNS view, and confirming reachability need the probe.
5. **`host-gateway` maps to the docker0 address** for containers on any network.
6. **Go's resolver puts `::1` before `127.0.0.1` for `localhost`,** and returns IPv4 hosts-file entries as `::ffff:` addresses. Unmap them (ADR 0001).
7. **A restarting container has no IP and can't be joined,** so WR008 must be checked before any probe runs.
8. **DNS failures are slow** (6 s and more). The product's DNS timeout must be short (2 s), and DNS probes must run in parallel to fit the 15 s deadline.
