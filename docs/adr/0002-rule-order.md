# ADR 0002: Rule order — what to build first and which finding wins

- **Status:** accepted (2026-11-13, between M0 and M1)
- **Inputs:**
  - `docs/research/failure-signatures.md`: how often each failure happens in the real world
  - `docs/research/rule-experiments.md`: what whyreach can actually observe for each failure

## Context

The first rule catalog (`INITIAL.md` §4.6) was written before any data. The research ranked real-world failures, and the experiments reproduced 17 of them on Docker Engine. Two orders now need to be fixed:

1. **Build order:** which rules ship first.
2. **Runtime precedence:** when several rules fire on one diagnosis, which finding is primary.

## Decision 1: catalog changes

- **Accept new rules:**
  - WR019: port not published, or published on another host address
  - WR020: the container's upstream DNS server fails
  - WR021: the host firewall rejects container-to-host traffic
  - WR022: no outbound NAT or forwarding
  - WR023: Docker Desktop's `network_mode: host` means the VM
  - WR024: a stale or hard-coded container IP
- **Defer WR025** (advertised-address redirect, e.g. Kafka). Its ID is reserved.
- **Change existing rules:**
  - WR005 decides from Docker metadata, never from the DNS rcode (experiment E1/E2).
  - WR006 also covers reaching a published port through the host's address.
  - WR007 gives a different fix depending on whether the user meant another container or the host.
  - WR016 is the last resort for timeouts. EHOSTUNREACH goes to WR024 when the address is on a Docker subnet, and to WR021 when it's the host.
- **Not detectable from outside the app:** the "client resolver bypasses Docker DNS" variant of WR024 (for example, an nginx `resolver 8.8.8.8` line) needs the app's config, and reading it would mean exec into the container.

## Decision 2: build order

Rank by real-world frequency first. Then prefer rules that need no probe container and no root, because they work in the default configuration (tier 2b off).

| When | Rules, in build order | Why these |
|---|---|---|
| **M1 slice** | WR007, WR004, WR002, plus a healthy control | Frequency ranks 1 and 2, plus the classic bind bug. Together they exercise metadata, host-read listeners and the probe container. |
| **M2** (rest of v0.1) | WR008 first (it gates probes), then WR020, WR010, WR012, WR019, WR011, WR005, WR009, WR006, WR003, WR001 | Covers ranks 3 to 8 and 12. |
| **v0.2** | WR015, WR024, WR014, WR013, WR016, WR021 | Rarer, weaker signals, or root needed for the strong form. |
| **v0.3** | WR017, WR018, WR022, WR023 | Advisory, platform-specific (Docker Desktop), or not reproducible safely. |
| **Deferred** | WR025 | — |

v0.1 grows from 10 to 14 rules. The extra rules are cheap because the evidence collectors are shared, and the lab scenarios already exist in `spikes/experiments/`.

## Decision 3: runtime precedence

Every rule belongs to one **layer**. The layers follow what a connection depends on, in order:

1. the destination is up
2. the source aims at the right target
3. the name resolves
4. a path exists
5. the right socket is listening
6. advisory checks

How findings are combined:
- **The primary finding** is the highest-confidence finding in the earliest layer that has one.
- **Consequences are suppressed.** Findings that only follow from the primary one are dropped through `Supersedes()`. Examples:
  - WR004 suppresses WR005 and WR016.
  - WR008 suppresses WR001, WR005 and WR016.
  - WR007 and WR002 suppress WR001.
- **Independent findings stay**, reported as "also found" in fix order. For example, if WR004 is primary and the destination also binds 127.0.0.1 (WR002), the diagnosis says: "after you connect the networks, api still only listens on loopback".

The full layer table is in `INITIAL.md` §4.5.

## Consequences

- **`Rule` gains `Layer()`**, and the engine sorts findings by layer, then confidence, then specificity.
- **The engine checks container state (WR008) before starting any probe.** A restarting container has no IP and can't be joined.
- **Lab scenarios:** the experiment Compose files are promoted to `test/lab/` in M1, starting with the slice: `wr007-localhost`, `wr004-separate-projects`, `wr002-loopback-bind` and `healthy`.
- **Refines ADR 0001's list of what needs the probe container.** With tier 2b off, only WR020, WR014 and WR016 of the reproduced rules lose their main evidence; WR021 and WR022, not reproduced yet, are expected to as well. WR005 and WR011 lose only their DNS confirmation, and WR009 needs no probe: the network name is enough.
- **Can't be tested on the dev box:**
  - WR021 needs a host or VM with ufw or firewalld rules.
  - WR017 needs a size probe to confirm an actual stall.
  - WR023 needs Docker Desktop.

  These are tracked in `INITIAL.md` §10.

## Amendment (2026-11-13, M1): WR008 ships with the slice

Decision 2 put WR008 first in M2 because it gates probes. M1's engine already needed that gate (no probe from a stopped source or towards a stopped destination), so WR008 moved into M1, with its fixtures, its lab scenario (`test/lab/wr008-not-running`) and its doc page. M2's list starts with WR020.

Implementing precedence also settled a detail: a finding is suppressed when **any** other finding's rule supersedes it, not only the primary's. For example, WR002 still drops WR001 when WR004 is the primary finding. Suppressed findings stay visible in the diagnosis.

## Amendment (2026-11-13, M2): the rest of v0.1

M2 built the other ten v0.1 rules in Decision 2's order. Precedence gained these pairs (`INITIAL.md` §4.5):

| Finding | Supersedes | Why |
|---|---|---|
| WR010 | WR001, WR003 | A server that is still starting listens on nothing, or not yet on its final port. |
| WR019 | WR001 | Nothing on the host listens because the container's port isn't published there. |
| WR006 | WR003, WR012 | The destination listens on the container port; the loopback "host service" is the published port. |
| WR011, WR009 | WR005, WR016 | The name can't resolve for a reason these explain. |
| WR005 | WR016 | — |
| WR012, WR003 | WR001 | — |

Decisions made while building them:

- **WR010 without a healthcheck** fires only (at medium) when the container started less than a minute before it was inspected and listens on nothing at all: "still starting" and "never going to listen" look the same otherwise. A container that listens on any port has started.
- **WR005** suggests the closest name by edit distance (one edit for names up to 3 characters, two up to 8, three beyond). A dotted name with no close container name counts as an external name and is left to WR020.
- **WR020** needs a control: when the target name matches no container, the probe also looks up the source's own name, which Docker's DNS answers without leaving the host. A timeout with the control resolved is high; SERVFAIL on a dotted name, no control, or the default bridge (no embedded DNS) is medium. NXDOMAIN, and a single-label name's SERVFAIL, are never WR020.
- **WR019** covers four host-side cases in priority order: published on another host address, published under another host port, listening but not published (medium when several containers do), and a container name used from the host.
- **WR012 and WR011** fire only on Linux Docker Engine, read from the `docker.version` evidence (Docker Desktop resolves `host.docker.internal` and reaches host services its own way).
- **Two scenarios must stay inconclusive** (`INITIAL.md` §6.3): a stale address (WR024, v0.2) and a server that closes every connection. No v0.1 rule fires on either.

## Amendment (2026-11-21, M6): WR015, the first v0.2 rule

Decision 2's v0.2 list starts with WR015: an `internal: true` network, with the target outside it. Decisions made while building it:

- **Metadata settles it** (Probe? no, as E8 found). The source's network namespace is only on internal networks: none without `internal: true`, and not on the default bridge either. The target lies outside them. So WR015 reaches high in the default configuration.
- **Containers' network attachments carry their networks' subnets**, from the same network list that gives the internal flag. "Outside" means the host, an address on none of the source's subnets, an address the source's `extra_hosts` map a name to (if it is off those subnets too), or a name with a dot that no container answers to.
- **A target on the source's own subnets is never outside.** Docker still gives an internal network's bridge its gateway address, and a container reaches the host there: measured on Engine 29.9.3, the connect was refused with nothing listening and accepted with a listener. An address on the subnet that no container holds is a stale address (WR024). Neither does WR015 fire for a container on another network (WR004) or a single-label name, which is more likely mistyped (WR005).
- **A connect from the source** that is refused or accepted shows a route exists, so WR015 doesn't fire. A timeout or "no route to host" instead of "network is unreachable" (ENETUNREACH) means the kernel had a route, so WR015 drops a level.
- **It supersedes WR016**, as `INITIAL.md` §4.5's table says (WR016 comes later in v0.2). Listener findings about the host (WR001, WR012) stay independent: once the network is fixed, they still apply.
- **The lab scenario** (`wr015-internal-network`) reaches a host service through `host.docker.internal`. `host-gateway` maps that name to the docker0 address, so the probe allowlist lets the connect run, and the harness listens there: the internal flag is the only thing wrong. The scenario passes with probe containers on and with the default config, and under `make lab-desktop` with nothing platform-specific.

## Amendment (2026-11-21, M6): WR024, the second v0.2 rule

WR024 is the stale or hard-coded container address. Measured on Engine 29.9.3 before building it:

- A connect from a container to an address on its own network's subnet that no container holds fails with "no route to host" (EHOSTUNREACH) after about 3.1 s, when ARP gives up. It is the same on an `internal: true` network. whyreach's connect gives up after 2 s, so its probe times out first. It gets EHOSTUNREACH sooner only when ARP for that address is already under way in the container, for example from an app retrying it.
- A connect to an address on the subnet of a Docker network the container isn't on is dropped silently, whether a container holds that address or not: a timeout, as between networks (E2).
- An app retrying such an address shows a socket in SYN-SENT to it in its network namespace's `/proc/net/tcp` most of the time (32 of 40 samples, retrying every second).

Decisions made while building it:

- **Only the first half of the catalog row.** WR024 fires when the source aims at an address on one of its own networks that no container holds: given literally, or through its `extra_hosts`. The second half, an app whose sockets still point at an old address it looked up once (nginx with a static upstream), needs the source's connection table. That is new evidence, to read from `/proc/<pid>/net/tcp` on Docker Engine, inside a probe container on Docker Desktop and through the netns executor as root. It isn't built yet; the doc page and the catalog row say so.
- **Only the source's own subnets.** An address on another network's subnet looks the same from the source whether a container holds it or not, and an address outside Docker could be any host.
- **Never the network's gateway.** Containers' network attachments now carry their networks' gateway addresses from Docker's network list, next to the subnets. They are known on internal networks too, where Docker gives the container no gateway. On Docker Desktop the host's interfaces don't show Docker's bridges, so the attachment is what keeps the bridge's own side (its VM's) from looking stale.
- **Probe? partly, as for WR005 and WR011.** Metadata infers it (medium). A connect from the source that got no answer, EHOSTUNREACH or a timeout, confirms it (high). A connect that was refused or accepted means something holds the address, and WR024 doesn't fire. "Network is unreachable" for the source's own subnet lowers it a level.
- **Incomplete metadata lowers it a level.** A container list that can't be read now leaves a record too (skipped, beside the list's gap), so WR005, WR015 and WR024 don't claim that no container has a name or an address when none could be listed.
- **It names who is on the network now.** The engine records every container on the source's networks for this case, as it does for a name that matches nothing (WR005). The finding lists them with their addresses, and when only one other container is there, the fix suggests it. On the default bridge, where names don't resolve, the fix moves the containers to a user-defined network instead.
- **It supersedes WR016,** as `INITIAL.md` §4.5's table says: nothing answers at that address, which explains a timeout.
- **A stopped container's fixed address is WR008's** (after the review). Measured on Engine 29.9.3: a stopped container with Compose `ipv4_address` or `ipv6_address` keeps it in its endpoint's `IPAMConfig`, in `GET /containers/{id}/json` and in the container list, while Docker clears `IPAddress`; a created container shows its fixed address as its `IPAddress` too; a stopped dynamic container keeps no address at all. Containers' attachments now carry the fixed address, and an address target matches a stopped container that has it, so the destination is that container and WR008 (layer 1) names it; WR024 has a destination there and doesn't fire. A container that is running or paused and holds the address comes first: Docker hands a stopped container's fixed address to new containers, and the stopped one then fails to start with "Address already in use". No lab scenario: a fixed address needs a fixed subnet in the Compose file, which could collide with networks on other machines; fixtures, an engine test and the client's decoding of the measured responses cover it.
- **The lab scenario is `inconclusive-stale-ip`, renamed `wr024-stale-ip`.** That scenario was already this case, waiting for WR024 (the M2 amendment above). The benchmark's records (`docs/research/agent-benchmark/`) keep its old name with the answer that was right then, `none`. Renaming it, instead of giving the old name new expectations, keeps those records and a later run's from mixing two questions under one name. It passes with probe containers on (WR024 high, the connect timed out) and with the default config (medium), and under `make lab-desktop`.
