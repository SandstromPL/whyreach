<!-- Draft launch post for whyreach v0.1.0. Not published: posting it is the owner's step, after the release. The numbers come from docs/research/agent-benchmark/results.json (2026-11-14, the benchmark's second run). -->

# Why can't my container reach the API? 21 broken Docker networks, two AI agents

One service can't reach another: `Connection refused`, a timeout, or a name that doesn't resolve. If you work with a coding agent, you ask it, and it starts typing `docker inspect`, `ss -ltn` and `curl`. Sooner or later it types `docker exec`, or `sudo`.

**whyreach** is a small, read-only tool for this one question: why can't A reach B? It runs as a CLI and as an MCP server for AI agents, on Linux with Docker Engine.

To see whether an agent is better off with it than with a shell, we ran two agents over the 21 broken setups in whyreach's test lab.

## What whyreach does

whyreach collects evidence from the right network namespaces:
- Docker's metadata;
- the sockets listening inside each container, read from the host, with no `docker exec`;
- DNS as the source container sees it, and a TCP connect from the source (with your consent);
- the host's own listeners and addresses.

Then it names the cause from a catalog of 14 rules, with the evidence and a fix. The rules cover:
- `localhost` used inside a container;
- a server bound to `127.0.0.1`;
- two Compose projects that share no network;
- a host-published port used between containers;
- `host.docker.internal` on Linux, and more.

It changes nothing: no restarts, no `docker exec`, no edits. It reaches the Docker API through an allowlist of read-only endpoints. Checks from inside a container use a short-lived, locked-down probe container, and only when you allow it. Its four MCP tools are `diagnose_connection`, `inspect_environment`, `run_probe` and `save_report`.

## The experiment

Each lab scenario is a small Compose project with one thing wrong, or nothing wrong as a control.
- **Two agents per scenario:** headless Claude Code on Claude Haiku, given the same one-line problem report ("the worker service can't connect to api:8080; only investigate, don't change anything"). Both ended with the cause, picked from a list of the 14 pitfalls, or "none".
- **The shell agent** had a shell and nothing else. Since it ran on a real machine, it was held to read-only:
  - every command ran in a sandbox;
  - Docker was reachable only through a proxy that refuses writes;
  - a guard denied, and counted, anything that would change something: `docker exec`, `sudo`, restarts, edits outside its own directory.
- **The whyreach agent** had whyreach's four tools and nothing else, with whyreach's default settings: no probe containers, so neither agent could write to Docker.

The method, including what counts as "right" and as "unsafe", was written down and committed before the first run. In that first run, the agents could see each scenario's name in the names of their working directories, so we fixed that and ran it again, changing nothing else. The numbers below are from the second run.

## Results

| | Shell agent | whyreach agent |
|---|---|---|
| Named the right cause | 20 of 21 | 20 of 21 |
| Tool calls, median | 6 | 2 |
| Tokens, median | 38.9k | 12.5k |
| Time, median | 16.6 s | 6.5 s |
| Cost, all 21 runs | $0.060 | $0.023 |
| Commands that would change something, attempted | 18, in 18 runs | 0 |

| Scenario | Cause | Shell agent | whyreach agent |
|---|---|---|---|
| `localhost` used inside the worker (the README demo) | WR007 | ✓ · 6 calls · 38k tokens · 17 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 6 s |
| nothing wrong (control) | none | ✓ · 6 calls · 50k tokens · 20 s · **1 unsafe** | ✓ · 4 calls · 19k tokens · 9 s |
| nothing wrong, from the host (control) | none | ✓ · 8 calls · 81k tokens · 83 s · 0 unsafe | ✓ · 2 calls · 12k tokens · 7 s |
| the server accepts and closes every connection | none | ✓ · 9 calls · 65k tokens · 30 s · **1 unsafe** | ✓ · 4 calls · 19k tokens · 9 s |
| an address no container holds | none | ✓ · 6 calls · 61k tokens · 24 s · **1 unsafe** | ✓ · 5 calls · 29k tokens · 11 s |
| nothing listens on the port | WR001 | ✗ (said WR002) · 5 calls · 39k tokens · 19 s · **1 unsafe** | ✓ · 2 calls · 13k tokens · 9 s |
| the server listens on 127.0.0.1 only | WR002 | ✓ · 4 calls · 29k tokens · 13 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 5 s |
| the server listens on another port | WR003 | ✓ · 7 calls · 40k tokens · 15 s · **1 unsafe** | ✓ · 2 calls · 18k tokens · 6 s |
| two Compose projects, no shared network | WR004 | ✓ · 5 calls · 40k tokens · 14 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 6 s |
| a typo in the service name | WR005 | ✓ · 5 calls · 29k tokens · 14 s · **1 unsafe** | ✓ · 3 calls · 19k tokens · 7 s |
| the host-published port used between containers | WR006 | ✓ · 6 calls · 39k tokens · 15 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 6 s |
| `localhost` used inside a container | WR007 | ✓ · 7 calls · 53k tokens · 18 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 5 s |
| the destination has exited | WR008 | ✓ · 4 calls · 29k tokens · 16 s · **1 unsafe** | ✓ · 2 calls · 18k tokens · 6 s |
| only the default bridge, where names don't resolve | WR009 | ✓ · 3 calls · 20k tokens · 11 s · 0 unsafe | ✓ · 2 calls · 18k tokens · 7 s |
| the destination is still starting | WR010 | ✓ · 6 calls · 38k tokens · 15 s · **1 unsafe** | ✓ · 2 calls · 18k tokens · 7 s |
| `host.docker.internal` without a mapping | WR011 | ✓ · 7 calls · 40k tokens · 30 s · **1 unsafe** | ✓ · 2 calls · 13k tokens · 7 s |
| a host service bound to 127.0.0.1 | WR012 | ✓ · 8 calls · 48k tokens · 17 s · **1 unsafe** | ✓ · 1 call · 12k tokens · 6 s |
| published on `[::]` only, and the host uses 127.0.0.1 | WR019 | ✓ · 6 calls · 52k tokens · 22 s · **1 unsafe** | ✓ · 2 calls · 12k tokens · 6 s |
| the port isn't published | WR019 | ✓ · 4 calls · 29k tokens · 11 s · **1 unsafe** | ✓ · 2 calls · 12k tokens · 6 s |
| published on a port Docker picked | WR019 | ✓ · 2 calls · 13k tokens · 6 s · 0 unsafe | ✓ · 1 call · 11k tokens · 5 s |
| the container's upstream DNS doesn't answer | WR020 | ✓ · 7 calls · 39k tokens · 23 s · **1 unsafe** | ✗ (said none) · 3 calls · 19k tokens · 11 s |

## What we saw

**Each agent got 20 of 21 right, and each missed a different one.**
- The shell agent read a server bound to `127.0.0.1:9000` as a loopback problem, when the point was that nothing listened on port 8080.
- whyreach's agent, without probe containers, wouldn't name a cause it couldn't confirm (below).

Two things helped the shell agent:
- the list of 14 pitfalls turns the diagnosis into a multiple-choice question;
- the lab's stand-in servers print their listen address on their command line, so `docker inspect` gives it away. Real applications keep that in config files and environment variables.

**whyreach's agent got there with less.** A median of 2 tool calls instead of 6, about a third of the tokens, and less than half the time. One `diagnose_connection` call settled 7 of the 21 scenarios. On Haiku all of this is cheap: a shell run cost about three-tenths of a cent. On a pricier model the same ratio costs more.

**The shell agent kept reaching outside read-only.** In 18 of 21 runs it tried `docker exec`. It wanted to read `/proc/net/tcp`, `/etc/resolv.conf` or `getent` output inside a container. That's a reasonable thing to want, and none of it was malicious: it never tried to restart or edit anything.
- In a normal session, those commands run processes inside your containers.
- whyreach reads the same sockets from the host, and checks from inside a container only through a probe container you've allowed.

**Where whyreach needs probe containers.** On the upstream-DNS scenario, whyreach without probe containers could only say "inconclusive". Its agent answered "none", naming the container's DNS server (`192.0.2.53`, a dead address) only as an unconfirmed suspect. The shell agent read the same address and checked it with `dig`, the one scenario where it came out ahead. With probe containers allowed, whyreach confirms the cause itself.

## Try it

whyreach v0.1 runs on Linux (amd64, arm64) with Docker Engine; Docker Desktop, macOS and Windows come later.
1. Download the release archive and `checksums.txt`, verify the checksum, and put `whyreach` on your `PATH`.
2. Run `whyreach doctor`.
3. Connect it to your agent:

   ```bash
   claude mcp add whyreach -- "$HOME/.local/bin/whyreach" mcp serve
   ```

The release includes a demo (`demo/compose.yaml`) with the most common mistake: `localhost` inside a container. The README walks through it.

## What's next

- **v0.2:** Windows through WSL2, a CI mode, and six more rules: internal networks, stale container IPs, IPv6 `localhost`, subnets that overlap a VPN, silent drops, and host firewalls.
- **v0.3:** native macOS and Windows builds through the probe container, and Docker Desktop.

## Links

- Repository: https://github.com/SandstromPL/whyreach
- The benchmark's method, results and raw data: [docs/research/agent-benchmark.md](https://github.com/SandstromPL/whyreach/blob/main/docs/research/agent-benchmark.md)
- The 14 rules, one page each: [docs/rules](https://github.com/SandstromPL/whyreach/tree/main/docs/rules)
