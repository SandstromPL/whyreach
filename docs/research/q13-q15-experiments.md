# Experiments for §10 Q13–Q15: DNS servers, repeated lookups, TCP reach

> **How to reproduce:**
> - E1's local half, E2 and E3's host-address cases: run `spikes/q13q15.sh`. Its query-counting DNS server is `spikes/dnscount`, and raw output goes to `spikes/out/q13q15/`.
> - E3's lab run: `TestLab` with `allow = ["loopback", "docker"]` under `[probe]` in both lab configs. That's a seven-line change to `setup()` in `test/e2e/lab_test.go`, not committed.
> - E2's agent count: `TestAgent` with every audit line logged. That's a one-line change in `test/e2e/agent_test.go`, not committed. Each scenario's audit lines are then counted.
>
> **When and where:** run on 2026-11-14 on the dev box (Ubuntu 24.04.5, Docker Engine 29.9.3), as a non-root user in the `docker` group, on `main` at `8fe0225` plus the spike.
>
> **Feeds:** the owner's decisions on `INITIAL.md` §10 Q13, Q14 and Q15. The questions were raised by the M4 reviews, and no experiment had tested them before.

## E1 (Q13): a link-local first DNS server

Since M4, whyreach never sends a query to an address on the probe block list. Some clouds' resolvers live at such addresses.

### Cloud images

This part is desk research from the providers' documentation. "Inferred" marks what the research couldn't confirm from a first-party source.

| Platform | Host's `/etc/resolv.conf` | Resolver | Link-local? |
|---|---|---|---|
| GCE: Ubuntu, Debian 12/13 (inferred), COS M133+ | systemd-resolved's stub (127.0.0.53) | 169.254.169.254, the metadata server | yes |
| GCE: RHEL and Rocky (Rocky inferred), Debian 11 and older, COS before M133 (both inferred) | the resolver itself | 169.254.169.254 | yes |
| GCE: IPv6-only VMs | — | fd20:ce::254, the metadata server | no, but it's the metadata server (below) |
| Oracle OCI: Ubuntu (other images inferred) | the stub | 169.254.169.254 | yes |
| AWS: Amazon Linux 2023, Ubuntu | the resolver itself (AL2023) or the stub | the VPC resolver at the VPC's base address + 2 (inferred from instance output) | no |
| AWS: a VPC without a DHCP option set (Nitro) | — | 169.254.169.253 | yes, but not the default |
| AWS: IPv6-only subnets | — | fd00:ec2::253 | no |
| Azure, GitHub Actions hosted runners, Codespaces | the stub | 168.63.129.16 | no |
| DigitalOcean, Hetzner | not checked | the providers' public resolvers | no |

Sources:
- **Google:** `docs.cloud.google.com/compute/docs/internal-dns`, `…/compute/docs/metadata/overview` and the COS M133 release notes.
- **AWS:** `docs.aws.amazon.com/vpc/latest/userguide/DHCPOptionSetConcepts.html`.
- **Microsoft:** `learn.microsoft.com/azure/virtual-network/what-is-ip-address-168-63-129-16`.
- **Oracle:** `docs.oracle.com/iaas/Content/Network/Concepts/dns.htm`.
- **Docker:** `docs.docker.com/engine/network/#dns-services`, and moby's `daemon/libnetwork/internal/resolvconf/resolvconf_path.go`.

What Docker gives a container:
- **On the default bridge:** a copy of the host's `resolv.conf`. Where that names only the stub, Docker takes systemd-resolved's upstream list instead, as moby's source shows; the docs don't say so.
- **On a user-defined network:** Docker's DNS at 127.0.0.11, which forwards to the host's servers from the host's side.

So on GCE and OCI:
- **Containers on user-defined networks:** never affected. That covers every Compose project.
- **Default-bridge containers:** affected on every image.
- **The host's own lookups, and host-network containers:** affected only where `/etc/resolv.conf` names 169.254.169.254 itself. That's RHEL/Rocky and older Debian and COS; Ubuntu, Debian 12/13 and COS M133+ query the stub, which is allowed.
- **Azure, GitHub's runners and Codespaces, DigitalOcean, Hetzner and AWS's defaults:** never affected.

**A gap the research found.** On IPv6-only VMs, GCE's metadata server is fd20:ce::254. Google's metadata documentation lists it as the IPv6 endpoint. The probe block list (`target.Blocked`) has AWS's fd00:ec2::254 but not this address. So on such a VM, whyreach would connect to GCE's metadata server over IPv6 if asked, connecting and closing without sending anything. The address belongs on the block list whatever Q13 decides.

### Local reproduction

The containers below were given `--dns 169.254.1.1`. That is a link-local address, so nothing was sent to it.

| Container | Its resolver | whyreach's result |
|---|---|---|
| On the default bridge | `nameserver 169.254.1.1` (Docker writes the given server into the container) | `probe dns example.invalid` is **skipped** with `policy_denied`: "not looked up: the first nameserver in /etc/resolv.conf, 169.254.1.1, which the app asks first, is on the probe block list". `diagnose` is **inconclusive**, with one gap. The gap says why, and that containers on user-defined networks ask Docker's DNS instead. |
| On a user-defined network | Docker's DNS, 127.0.0.11, which forwards to 169.254.1.1 | `probe dns peer`, a name Docker knows, is **ok** through 127.0.0.11. Not affected. |

The first row is what a default-bridge container gets on a host whose resolver is link-local. Docker copies the host's resolver into it, or, on a systemd-resolved host, the stub's upstream servers. A host-network container shares the host's own `resolv.conf`, so it's affected only where that file names the link-local address. Compose projects run on user-defined networks, which is the second row.

## E2 (Q14): do repeated lookups of one name reach its DNS server?

`dnscount` answers every A question with 192.0.2.1 and prints each question it receives. The name chooses the TTL: 0 for most names, 60 for names under `ttl60`. Each row is 10 `whyreach probe dns` lookups of one name from a container (probe containers on), counted at the server.

| Path | Answer's TTL | Lookups | Questions the server received |
|---|---|---|---|
| User-defined network, through Docker's DNS (127.0.0.11) | 0 | 10 | 10 A, 10 AAAA |
| User-defined network, through Docker's DNS | 60 | 10 | 10 A, 10 AAAA |
| Default bridge, straight to the server | 0 | 10 | 10 A, 10 AAAA |
| Default bridge, straight to the server | 60 | 10 | 10 A, 10 AAAA |

- **Every lookup reached the server.** Neither Docker's DNS nor whyreach caches answers, even when the answer allows 60 seconds. A cache wouldn't help anyway: the domain's owner sets the TTL, and an attacker answers with 0. The host's own path through systemd-resolved wasn't measured, because that would mean changing the host's DNS.
- **The rate limit didn't apply here.** Each CLI call is its own process, and the limit applies per process, so 10 lookups took about a second. Through MCP, one server process applies the limit of 30 checks a minute.

**How often agents repeat a lookup.** This was one run of the 21 agent scenarios on Claude Haiku: all passed, and the run cost $0.03. A name counts once for each tool call that resolves it: `diagnose_connection`'s host, `run_probe dns`'s name, `run_probe tcp`'s host.

| Lookups of one name in a scenario | Scenarios |
|---|---|
| 1 | 16 (including WR020's outside name, `example.com`) |
| 2 | 4 |
| 3 | 1 (`localhost` in `wr019-random-port`) |

## E3 (Q15): TCP probes outside Docker's networks

### A container reaching a published port through the host's LAN address

This was run with probe containers on. The client container is on a user-defined network.

| `[probe] allow` | Server | Result |
|---|---|---|
| Default (`loopback`, `rfc1918`, `docker`) | Published on the host's LAN address, on the client's network or on the default bridge | **No problem reproduced**: the client connected |
| Default | Published on 127.0.0.1 only | **Cause identified**: WR006, high |
| `loopback`, `docker` | Published on the host's LAN address (either network) | **Inconclusive**, with one gap: "TCP connect from the client: policy" |
| `loopback`, `docker` | Published on 127.0.0.1 only | **Cause identified**: WR006, high, from Docker's metadata, plus the same gap |

The servers here are the lab's server, which holds a connection open. A first run used the spike probe's `serve`, which closes each connection as soon as it accepts it. whyreach reported that as "accepted and closed at once" (inconclusive), which is correct for such a server, but it isn't a healthy service.

### The full lab with the narrowed allowlist

`TestLab` with `allow = ["loopback", "docker"]` in both configs passed all 42 runs (21 scenarios, with probe containers off and on). No lab scenario connects to a private address outside Docker's networks. So the lab can't show what the narrowing costs; the host-address case above is the only measured cost. A service on the LAN or in a cloud VPC at a private address would lose its connect check the same way. That case wasn't measured.

## What the experiments changed

- **Q13 hits fewer setups than first said.** By default only GCE and Oracle OCI give a VM a link-local resolver; AWS does only in a non-default VPC setup. Even there, Compose projects are unaffected. Default-bridge containers are affected on every GCE image, and the host's own lookups only on images whose `resolv.conf` names the resolver directly. Separately, GCE's IPv6 metadata address is missing from the block list.
- **Q14's channel is real, at the full rate the limit allows, on every path tested.** Caching doesn't blunt it. Agents rarely look up the same name more than twice, so a small budget per approved name would not have changed any scenario.
- **Q15's narrowing has a cost the lab can't see.** Checks to the host's LAN address become inconclusive, and by the same mechanism so would checks to LAN and VPC services. Findings that Docker's metadata settles, like WR006, still stand.
