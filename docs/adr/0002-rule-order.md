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
- **The second scenario that must stay inconclusive** (after the review) is `inconclusive-outside-allowlist`: a target the probe policy doesn't connect to by default, so whyreach sends nothing and can only say how to allow the check. `INITIAL.md` §6.3 records why it holds up after all six v0.2 rules.
- **The lab scenario is `inconclusive-stale-ip`, renamed `wr024-stale-ip`.** That scenario was already this case, waiting for WR024 (the M2 amendment above). The benchmark's records (`docs/research/agent-benchmark/`) keep its old name with the answer that was right then, `none`. Renaming it, instead of giving the old name new expectations, keeps those records and a later run's from mixing two questions under one name. It passes with probe containers on (WR024 high, the connect timed out) and with the default config (medium), and under `make lab-desktop`.

## Amendment (2026-11-21, M6): WR014, the third v0.2 rule

WR014 is the IPv6/IPv4 mismatch on loopback. Measured on Engine 29.9.3 before building it, in a throwaway project (glibc and musl images, Node.js 18.19 and 24.22, Go, Python, libpq, `redis-cli`, busybox `wget`):

- **What `localhost` means.** Docker writes `127.0.0.1 localhost` and `::1 localhost ip6-localhost ip6-loopback` into every container's `/etc/hosts`, on IPv4-only networks as on IPv6 ones, and the container's loopback has `::1`. With IPv6 disabled in the container (`net.ipv6.conf.all.disable_ipv6=1`), Docker leaves the `::1` line out, and a connect to `[::1]` fails with "cannot assign requested address". On the dev box (Ubuntu), the host's `localhost` is `127.0.0.1` alone.
- **The order a client gets.** musl puts `::1` first. glibc does too, except that a lookup with `AI_ADDRCONFIG` leaves `::1` out when the container has no IPv6 address but loopback (Docker's default IPv4-only networks); on an IPv6 network it puts `::1` first. Go's resolver puts `::1` first.
- **Clients against a server on `127.0.0.1` alone.** Node.js 18.19 fails with `ECONNREFUSED ::1` on both kinds of network. Node.js 24.22 connects (it falls back by default), and without its fallback (`--no-network-family-autoselection`) it connects on an IPv4-only network, where its lookup leaves `::1` out, and fails on an IPv6 one. Go and Python try `::1`, then connect to `127.0.0.1`; on musl, libpq and `redis-cli` fall back too, while busybox `wget` tries `[::1]` alone and fails.
- **Servers told to listen on `localhost`.** Node.js 18.19 and 24.22 bind `[::1]` alone. Against such a server, Node.js 24.22 in a glibc container on an IPv4-only network fails with `ECONNREFUSED 127.0.0.1`, with its fallback or without, while Node.js 18.19 and Go connect; on an IPv6 network all three connect.
- **What the listener table shows.** `/proc/net/tcp6` shows a `[::]` socket the same whether it has `IPV6_V6ONLY` or takes both families; only a connect over IPv4 tells them apart. `net.ipv6.bindv6only` is 0 on the host and in containers.
- **A port published on the host's loopback** (`ports: ["127.0.0.1:P:C"]`): Docker's proxy listens on `127.0.0.1:P` alone and `[::1]:P` is refused. Published on every address, the proxy listens on `0.0.0.0:P` and `[::]:P`, and `[::1]:P` gets through.

Decisions made while building it:

- **Both directions on loopback.** An IPv4-only listener with `::1` among the target's addresses, and the converse: a server on `::1`, or on an IPv6-only `[::]`, with `127.0.0.1` among them. The converse is the same pitfall with the same evidence and fix, and the measurements show it biting as often: a server told to listen on `localhost` binds `::1`, and a recent Node.js client on Docker's default networks then never tries `::1`. Without WR014 both were inconclusive.
- **Only loopback.** ADR 0001's accidental case, a `[::]` listener with `IPV6_V6ONLY` that another container reaches over IPv4, isn't about `localhost` and would need its own evidence path (a refused IPv4 connect beside a `[::]` listener, from another network namespace): not built.
- **WR019 keeps the binding on another address.** From the host, WR014 judges a published port only when a binding covers one of the addresses the target means; otherwise the binding's address is the problem (`wr019-ipv6-only`: published on `::`, `localhost` meaning `127.0.0.1` alone), and WR014 doesn't fire.
- **Confidence follows what whyreach can see of the app's client: nothing.** High when the target leads only to the family the listener lacks (a literal address, or a `localhost` that means one address), since every client fails. Medium when the target means both and one works: the app's client decides. Low when the listeners couldn't be read and only the connects show it. Probe? yes: without a connect from the source WR014 isn't evaluated, and the probe's gap says how to allow it. The listeners must agree: a listener that takes the refused family, or a refused or closed connect to the family that has one, and WR014 doesn't fire.
- **The verdict follows a medium WR014 although whyreach connected** (`INITIAL.md` §4.4). Rule 1 would otherwise call it "no problem reproduced", because whyreach's own connect works through the other address; but the app's client, not whyreach's, picks the address. Rules mark this with `rules.ReachesPartly`; only WR014 does, and only a primary finding at medium or higher changes the verdict. The summary names the address that worked and the one that was refused.
- **WR007 no longer guesses for a source in another container's network namespace** when that namespace's listeners can't be read: in a sidecar setup `localhost` is meant to reach the other container. Found by the scenario's first run under `make lab-desktop` without probe containers, where WR007 claimed at medium that `localhost` meant app alone.
- **No new evidence.** The source's lookup, a connect to each address and the listeners already existed; WR014 supersedes nothing (WR001 needs no listener on the port, WR014 one).
- **The lab scenario** (`wr014-localhost-ipv6`): app shares proxy's network namespace, proxy listens on `127.0.0.1:7100` alone, and app connects to `localhost:7100`. With probe containers on, WR014 is primary at medium and the verdict likely_cause; with the default config, inconclusive with the gap; the same under `make lab-desktop`. The host's published-port case can't run on the dev box, whose `localhost` is `127.0.0.1` alone: fixtures and an engine test cover it.

## Amendment (2026-11-21, M6): WR013, the fourth v0.2 rule

WR013 is a Docker subnet that overlaps a VPN or LAN route. Measured before building it, on Engine 29.9.3 with throwaway networks, and in an unprivileged user and network namespace (`unshare -Urn`) with made-up interfaces and ranges, so nothing in the host's own namespace changed:

- **Docker's side.** The host's route lookup for an unused address in a Docker network's subnet picks the network's bridge (Docker's `proto kernel` route; `linkdown` while no container is attached). A connect from the host fails with "no route to host" once ARP gives up, so whyreach's 2 s connect times out first; a container on another network times out (Docker drops traffic between its networks). E9 had only looked the route up. Before WR013, both diagnoses were inconclusive.
- **Route selection, in the namespace.** A Docker-like `/24` inside a VPN-like `/16` wins for its addresses (the most specific route); a VPN `/24` inside a Docker `/16` wins for its own (the reverse direction); at equal length, the kernel route (metric 0) wins over a VPN's with metric 50; a routing rule that sends a range to another table wins over the bridge's own route in the main table. `ip route get fibmatch` names the entry the kernel picks and its table, and a route dump lists every table's routes.
- **Bridge names.** A user-defined bridge network's interface is `br-` and the first 12 hex digits of its ID (no option names it); the default network's is `docker0`, as its options say.

Decisions made while building it:

- **One direction:** a Docker subnet that takes a VPN's or a LAN's range, so traffic meant for a machine there goes into Docker's bridge: from the host, from a container on another network (through the host's routing table) and from a container on that network (its own subnet). Not built: the reverse, a VPN route more specific than a Docker subnet (or a rule's table) that takes host-to-container traffic away from the bridge, which would need route lookups of containers' own addresses; and a VPN client inside a container (`network_mode: service:vpn`), whose routes are in its own namespace.
- **The evidence** is a `host.route` record for each of the target's addresses (at most 2) that lies in a Docker bridge network's subnet, isn't its gateway and that no container holds: the table entry the kernel picks (RTM_GETROUTE with `RTM_F_FIB_MATCH`), the unicast routes in any table that cover the address (prefix, interface and table only: no gateway, source address or metric; default routes and their `/1` halves dropped, as they cover every address), and the Docker networks holding it, with their bridges, from Docker's network list (read for a diagnosis from the host too, which hadn't needed it). The record is made after the probes, so a lookup's answer counts, but needs none of them.
- **No new dependency.** The standard library's and `golang.org/x/sys`'s netlink support cover the two requests; `vishvananda/netlink` (allowed, and planned in `INITIAL.md` §4.8) isn't added: its source wasn't in the module cache, and two requests don't justify a library and a larger binary. A test runs the lookups against made-up routes in an unprivileged network namespace, and is skipped where that isn't allowed.
- **Confidence:** high when a route that isn't Docker's and isn't a default route covers the address too; medium without one, except on the source's own network, which stays WR024's; one level lower when some containers' metadata couldn't be read. Probe? no: a connect that something answers rules WR013 out, and one that gets none is cited.
- **It supersedes WR016 and WR024.** WR024 fires alongside WR013 only on the source's own network with a competing route, which shows the address is meant to be a machine behind the VPN or LAN.
- **Boundaries:** an address a container holds (or a stopped container's fixed address) is a destination (WR004, WR008); the host's own addresses and the networks' gateways are the host's (WR001, WR011, WR012, WR019); a source only on internal networks is WR015's; macvlan and ipvlan networks share the LAN's range on purpose and have no bridge of the host's.
- **Platforms:** on Docker Desktop its VM routes the containers' traffic, so the record is unsupported, with advice to compare the subnets with the VPN's routes by hand (`INITIAL.md` §3.7); in whyreach's image without `--network host` the host's routes are out of sight, as its other host-side reads are; elsewhere than Linux the lookup is unsupported.
- **Redaction:** routes that aren't Docker's map the user's other networks, so their ranges, their interfaces (unless named by a plain word, which identifies nothing and would match prose) and the host's own addresses on those interfaces get pseudonyms in every redacted report, private or not.
- **The lab scenario** (`wr013-subnet-overlap`) is the medium case: the host connects to an address in the project network's subnet that no container holds. WR013 is primary at medium with probe containers on and with the default config; under `make lab-desktop` the record is a gap. The high case can't be made without changing the host's routes: fixtures, an engine test and the namespace test cover it.
- **While building it,** WR014's explanation turned out to capitalize a container's name at its start (`app` became `App`); only a leading "the" gets a capital now.

## Amendment (2026-11-21, M6): WR016, the fifth v0.2 rule

WR016 is the last resort for timeouts: a connect that nothing answered means a silent drop. Measured before building it, in an unprivileged user and network namespace (`unshare -Urn`, a client and a server namespace joined by a veth pair, documentation addresses, firewall rules and routes inside those namespaces only), and on Engine 29.9.3 with throwaway networks:

- **The errno split, in the namespace.** A firewall rule that drops, on the server's side (INPUT) or on the client's (OUTPUT, which doesn't return EPERM to a TCP connect), times out, at 2 s and at 8 s alike; so does a route on the server's side that drops the reply. A reject with `icmp-host-prohibited`, `admin-prohibited` or `host-unreachable` gives EHOSTUNREACH at once, `net-prohibited` ENETUNREACH, `tcp-reset` or `port-unreachable` ECONNREFUSED. On the client's side, a `prohibit` route gives EACCES, `blackhole` EINVAL, `unreachable` EHOSTUNREACH, and no route ENETUNREACH, all at once. An address on the link that nothing holds gives EHOSTUNREACH once ARP gives up, after about 3.1 s; a second connect while ARP for it is still under way gets it sooner (here after 1.06 s), as the WR024 amendment found.
- **A full accept queue times out too.** A listener whose app never accepts (backlog 0): the first connect completes and waits in the queue, and every later one times out, at 2 s and at 8 s. `/proc/net/tcp` shows the waiting connection as the listener's `rx_queue` (1 here); its `tx_queue` is 0, so the queue's limit isn't shown. A server stopped with SIGSTOP whose queue has room still completes the handshake: connected.
- **Docker.** On a network created with `-o com.docker.network.bridge.enable_icc=false`, a container's connect to another container's address times out at 2 s, while the destination listens on `0.0.0.0` (its listeners were read) and its name resolves; the host's connect to the same address works. `GET /networks` and `docker network inspect` show the option as `"false"` (the default bridge shows `"true"`). With both containers on a second, ordinary network too, Docker's DNS answered with the ordinary network's address only and the connect worked; a connect to the address on the ICC-disabled network timed out. Before WR016 the diagnosis was inconclusive ("the connect timed out, and no rule explains it yet"). A paused destination is WR008's: the probes are skipped.

Decisions made while building it:

- **Only timeouts.** WR016 fires when every connect the source made through the target's name or literal address timed out; one that was answered (accepted, refused, closed, reset), got EHOSTUNREACH or ENETUNREACH, or that the source's kernel refused to send (EACCES, EINVAL, EPERM) rules it out. This settles decision 1's split: a timeout is WR016's unless a rule that explains it supersedes it (WR004, WR005, WR008, WR009, WR011, WR013, WR015, WR024, already declared, and WR021 when it is built); EHOSTUNREACH stays WR024's and WR013's on a Docker subnet and WR015's, and goes to WR021 for the host; ENETUNREACH is WR015's; EACCES, EINVAL and EPERM have no rule. A connect to an address from Docker's metadata isn't how the app connects and doesn't count, so in `wr004-separate-projects`, where the name doesn't resolve, WR016 has nothing to judge, and by address WR004 suppresses it (`INITIAL.md` §2.3).
- **Confidence follows what names the dropper.** High when the network that holds the address, which the source shares, disables inter-container communication: Docker's metadata names the dropper, and its listeners don't matter. Medium when a container on a network the source shares (or the host itself) holds the address and its listeners show it would have answered: a listener that takes the connect with nothing in its accept queue, or none, so its kernel would have refused. Low when the listeners couldn't be read, when connections wait in the queue (the app may have stopped accepting, which times out as well), when the host connects to a container (nothing of Docker's stands in between on a bridge network, so the drop is in the container's namespace, or the network is a macvlan or ipvlan one the host can't reach by design, and the attachment doesn't record the driver), and for an address outside Docker. Probe? yes: without the source's connect, WR016 isn't evaluated.
- **Before a listener finding.** With a loopback-only listener (WR002) or none (WR001), a timeout instead of a refusal already lowered those rules a level; now WR016 (layer 4) is primary at medium and they stay as "also found": the drop has to go before the listener fix can help.
- **New evidence, small.** Each listening socket records its accept queue's length (`queued`, when not 0). Each network attachment records `icc_disabled`, from the network list's options (the option alone is read, as the bridge's name is). The route lookup (`host.route`, WR013's) also runs for an address outside every Docker network's subnet that the source's connect timed out on, keeping the chosen route even when it is the default one: from a container the traffic leaves through its gateway, so the host's routes say where it went, and a private address that only the default route covers usually means a missing route (a VPN that is down). At most 2 lookups in all, only where Docker Engine runs on this machine, and redacted as before (a default route's prefix names nothing and is left alone; its interface gets a pseudonym).
- **The host's side is WR021's slot.** For a target on the host, WR016 is medium with the host's listeners and points at the host's firewall; WR021 will take that case (a rejecting firewall's EHOSTUNREACH as well as a dropping one's timeout, with a listener on the host) and supersede WR016 there. The doc page says so.
- **Docker Desktop.** Traffic between containers, or to an address on the source's own network, stays in Docker Desktop's VM, where Docker's rules are the same: judged as on Engine, with the listeners from probe containers. Traffic that leaves the VM (to the host or `host.docker.internal`, a container from the WSL2 distro, an address outside Docker) passes Docker Desktop's own network stack, where a timeout says nothing whyreach can stand behind: WR016 doesn't fire there, and no route is looked up.
- **ICC disabled could be a rule of its own** (proposed to the owner, not added). Docker's metadata alone settles it, so as its own rule (Probe? no) it would reach high in the default configuration, before any connect; inside WR016 it waits for the timeout (Probe? yes) and gives the probe's gap without probe containers. Moving it out would take its fixtures, its part of the doc page and the lab scenario's expectations with it.
- **The lab scenario** (`wr016-silent-drop`): worker and api share the project's network with inter-container communication disabled. With probe containers on, WR016 is primary at high and the verdict cause_identified; with the default config, inconclusive with the probe's gap; the same under `make lab-desktop`. It is the only drop the lab can make without pulling an image or changing the host. In the other scenarios that time out, WR016 is only suppressed (`wr024-stale-ip` by WR024, `wr013-subnet-overlap` by WR013: the harness's new `suppressed` expectation checks it) or has nothing to judge (`wr004-separate-projects`, where the name doesn't resolve, and `wr015-internal-network`, whose connect gets ENETUNREACH; both list WR016 under `must_not_fire`, which covers suppressed findings); the two scenarios that must stay inconclusive have no timeout.

## Amendment (2026-11-21, M6): WR026 gets its ID

The owner's decision on WR016's proposal: a network that disables inter-container communication (`com.docker.network.bridge.enable_icc=false`, or the daemon's `"icc": false` for the default bridge) gets a rule ID of its own, WR026 (layer 4, from Docker's network options alone, Probe? no). It isn't part of v0.2: it comes after v0.2's six rules, and until it is built WR016 keeps the case as its high one. WR025 stays reserved for the advertised-address redirect.

## Amendment (2026-11-21, M6): WR021, the sixth v0.2 rule

WR021 is the host's firewall turning away container-to-host traffic. Measured before building it, in an unprivileged user and network namespace standing in for the host (`unshare -Urn`: a veth pair for a bridge and its container, a dummy interface for a LAN address, documentation addresses, nftables rules inside the namespace only), and on Engine 29.9.3 with throwaway resources; nothing of the host's firewall, routes or sysctls changed:

- **The errno split.** With a rule set that accepts loopback and established traffic and drops the rest for the port (ufw's default "deny incoming"), the container's connect times out, at the host's bridge address and at its LAN address alike, while the host's own connect to either is accepted. A reject with `icmp-host-prohibited`, `icmpx admin-prohibited` (firewalld's) or `host-unreachable` gives the container EHOSTUNREACH at once; a reject with a TCP reset, or a plain `reject` (port-unreachable), gives ECONNREFUSED; the host's own connect is accepted in every case. ufw's own source fits: its packaged rules accept `-i lo`, its deny drops, and its reject rules for TCP send a reset.
- **What the comparison tells apart.** With the service on `127.0.0.1` only, the same rules give the container a timeout or EHOSTUNREACH, and the host's own connect to the bridge address is refused: still an answer. A rule without the loopback exemption treats both alike (both time out, or both get EHOSTUNREACH). A reject or drop in the container's own namespace (OUTPUT) gives the container EHOSTUNREACH or a timeout while the host's own connect is accepted: connects alone can't tell it from the host's firewall.
- **A full accept queue** (a backlog of 0, never accepting) times out the host's own connect too. On Docker, a host listener on docker0's address with its queue filled made a container's connect time out (WR016's accept-queue case, at low: its first run on Docker) and the host's own connect as well.
- **A stand-in for the lab.** A classic BPF socket filter that passes only what arrives on loopback (ifindex 1) makes a listener behave like ufw's drop: in the namespace, the container's connect timed out, the host's own was accepted, and the listener's queue stayed empty. On the dev box, attaching any socket filter needs `CAP_NET_ADMIN`: refused to the user, under `unshare -Ur`, and to a container with Docker's default capabilities, allowed with `--cap-add NET_ADMIN`. A reject can't be emulated without netfilter.

Decisions made while building it:

- **No firewall rules are read.** nftables and iptables need root, ufw's and firewalld's state is in files whyreach doesn't read (only `resolv.conf` and `hosts`), and parsing firewall rules is out of scope (`INITIAL.md` §2.2). WR021 compares connects instead. Reading the firewall's state would need an `INITIAL.md` change: the owner's decision, proposed rather than built.
- **The host's own connect, for comparison.** When a container's connect to one of the host's own addresses was rejected (EHOSTUNREACH), timed out, or was refused while a listener of the host's takes that address, the engine connects to the same address and port from whyreach's own network namespace, the host's: a `probe.tcp` record in the host's context, via `control`, at most 2. It goes through the guarded host executor like every probe: the allowlist (the source's connect to that address was allowed), Q15's free list (the host's own addresses need no approval through MCP), a token of the rate limit, and a probe sent in the audit entry. It is the target's own host:port, so one target per call holds. It isn't made for a port a container publishes there (Docker's NAT and docker-proxy, where INPUT rules may not apply), from the host or a host-network container, or where Docker Engine doesn't run on this machine. `TCPProbe.ByName` excludes it: it isn't how the app connects.
- **The errno split, settled for the host's side.** EHOSTUNREACH to one of the host's addresses is WR021's (a reject: nothing else between a container and its host answers that way). A timeout is WR021's when the host answers its own connect (accepted, refused, or rejected too), or, when that connect couldn't be made, when a host listener takes the address with an empty accept queue; it stays WR016's when the host's own connect times out too. A refusal is WR021's only when the host's own connect was accepted (a reject that sends a reset); otherwise WR001's, WR012's or WR006's. ENETUNREACH stays WR015's, and EHOSTUNREACH on a Docker subnet WR024's and WR013's.
- **Confidence.** High when the host answers its own connect, or rejects it too (then even from a shared namespace: the host's own connect can't pass through the container's firewall). One level lower when the source runs in another container's network namespace (`network_mode: container:`), where a VPN client's kill switch does the same. Without the host's own connect: medium for a reject, or for a drop in front of a listener that takes the address with an empty queue; low for a reject when the host's listeners couldn't be read either. Probe? yes: the source's connect is the evidence.
- **It supersedes WR016**, whose host case changed in one way: when the host's own connect timed out too, WR016 cites it and says the drop covers the host's own traffic (a rule for every source, or an app that stopped accepting), with a fix that looks for that, instead of pointing at a firewall that keeps Docker's networks out.
- **Boundaries:** a host-gateway name Docker Engine doesn't map (WR011) leaves no connect; a service on the host's loopback that refuses (WR012) gets no comparison, and with a firewall in front WR021 comes first and WR012 stays as also found; a port a container publishes, on every address or on the host's loopback only (WR006), is out; from the host (WR019) the connect is the host's own; EHOSTUNREACH that isn't the host's (WR024, WR013) and ENETUNREACH (WR015) are out. Each has a must-not-fire fixture (33 fixtures in all), and the host scenarios list WR021 under `must_not_fire`.
- **Platforms.** `linux-engine`, and `wsl2-engine` with the WSL2 VM as the host. On Docker Desktop (`wsl2-desktop` and the others) the host the containers reach is Windows or macOS, behind Docker Desktop's own network stack: WR021 doesn't fire and no connect is made; the host's listeners are a gap, as for WR012.
- **The lab (and `INITIAL.md` §10 Q9).** `wr016-host-stalled`, a host service that stopped accepting: both connects time out, WR016 is the lead at low and WR021 must not fire. It is the one scenario where the host's own connect runs for real. `wr021-host-firewall` is WR021's own case, skipped unless `WHYREACH_LAB_HOST_FIREWALL` says a host firewall was set up for it, on a machine meant for it: the owner's WSL2 lab, in a throwaway distro with ufw turned on (§10 Q9). Until it runs there, WR021 hasn't met a real host firewall.

## Amendment (2026-11-25): the real-case check's findings

The real-case check (`INITIAL.md` §6.5, `docs/research/real-cases.md`) ran whyreach on 15 broken setups from Stack Overflow, the Docker forums and GitHub issues. Three of its findings change rules; the order of layers doesn't change.

- **WR007 and WR001 for a container's own `localhost`.** WR007 used to fire whenever nothing in the source listened on the port, and superseded WR001. When the server should have run in the source itself and simply wasn't listening (a missing `--api-port`), that sent the user to look for another container, at high confidence. Now a lone source (no other container shares its network or Compose project, no container publishes the port, nothing on the host listens on it, and every container's sockets were read: `loneLoopback`) is WR001's, with the source as the destination, and WR007 stays out. When the source isn't alone but nothing anywhere listens on the port, WR007 drops to medium, and its fix lists what the containers on the source's networks do listen on.
- **WR007's fix for a published port.** When another container publishes the port on the host, WR007's fix names that container and its own port (plus a shared network when they have none) instead of `host.docker.internal`, which only reaches it the long way, through the host.
- **WR009 for a name no container answers to on the default bridge.** A source only on the default bridge can't resolve any container's name, so a short name that matches no container is WR009's, at medium. WR005 still stays out on the default bridge; a name with a dot stays an outside name.

Each has fixtures that fire and that must not; `make lab` passes its 27 scenarios unchanged, and the real cases ran again afterwards (reported next to the first run in `docs/research/real-cases.md`, not in its place).
