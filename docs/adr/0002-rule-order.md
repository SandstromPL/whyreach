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
