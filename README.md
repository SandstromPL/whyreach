# whyreach

Read-only network diagnosis for Linux and Docker, built for developers and their AI coding agents. It runs as a CLI and as an MCP server.

> **Status: pre-alpha.** M2 works on Linux with Docker Engine: the CLI and an MCP server diagnose the 14 v0.1 failures, from `localhost` used inside a container to an upstream DNS server that doesn't answer (the catalog is in [INITIAL.md §4.6](INITIAL.md), each rule documented in [docs/rules](docs/rules)). The design is in [INITIAL.md](INITIAL.md), and the rules for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

When one container can't reach another, whyreach collects evidence from the right network namespaces (Docker metadata, listening sockets, DNS and TCP probes) and explains the cause, without changing anything.

```
$ whyreach --from container:shop-worker-1 api:8080
✗ worker → api:8080 — cause identified (high)

WR002  api listens only on 127.0.0.1:8080 inside its container
       …
  fix    Make the server in api listen on 0.0.0.0:8080 (or [::]:8080), …
```

`--from` takes `host`, `container:<name|id>` or `service:<name>[@<project>]`; add `--json` for machine-readable output. Exit codes: 0 no problem reproduced, 1 cause found, 2 inconclusive, 3 usage error, 4 internal error.

Other commands: `whyreach inspect host|container NAME|service NAME|network NAME`, `whyreach probe tcp HOST:PORT|dns NAME|listeners [--from SOURCE]`, and `whyreach doctor`, which checks that everything works here.

## With an AI coding agent (MCP)

```sh
claude mcp add whyreach -- /absolute/path/to/whyreach mcp serve
```

The server offers four tools: `diagnose_connection`, `inspect_environment`, `run_probe` and `save_report`. They return a compact structured result that leads with the verdict, plus a text summary. Every call is recorded in `~/.local/state/whyreach/audit.jsonl`.

DNS and TCP checks from inside a container need **probe containers**, which are off by default because they write to Docker (a short-lived, hardened, labeled container, removed afterwards). Turn them on in `~/.config/whyreach/config.toml`:

```toml
[permissions]
probe_containers = true
```

Without them, whyreach still settles most causes from Docker metadata and the containers' listening sockets, and says what it could not check. Through MCP, when a probe container would change the answer, whyreach asks once per session (if the client supports elicitation); an approval lasts until the session ends.

Run as root on the Docker host (`sudo whyreach --from container:worker api:8080`), whyreach doesn't need probe containers: it enters the containers' network namespaces itself, with no Docker write, under the same probe limits (`netns = false` under `[permissions]` turns that off). Only if it can't enter one, and you allow probe containers, does a probe container stand in. It then reads root's config and writes root's audit log, so use `sudo`, not `sudo -E`. Use root for the CLI only; run the MCP server as a regular user.

Probe targets are limited by `[probe] allow` (by default `loopback`, `rfc1918` and `docker`: the subnets of Docker's networks) and `rate_per_minute` (30). Link-local and cloud-metadata addresses are always refused.

## Development

```bash
make build   # static binary in bin/whyreach
make test    # unit tests and rule fixtures (no Docker, no root)
make lint    # golangci-lint v2
make cross   # compile check for macOS and Windows
make lab     # the failure lab in test/lab (needs Docker)
make lab-root   # the same lab as root, where whyreach enters network namespaces itself (asks for your sudo password)
make lab-agent  # a headless agent diagnoses each lab scenario through MCP (needs the claude CLI)
```

## License

Apache-2.0. See [LICENSE](LICENSE).
