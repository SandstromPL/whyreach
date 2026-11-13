# whyreach

Read-only network diagnosis for Linux and Docker, built for developers and their AI coding agents. It runs as a CLI and as an MCP server.

> **Status: pre-alpha.** M1, the first vertical slice, works on Linux with Docker Engine: the CLI diagnoses four failures (WR008 destination not running, WR007 `localhost` inside a container, WR004 no shared network, WR002 loopback-only bind). The MCP server comes in M2. The design is in [INITIAL.md](INITIAL.md), and the rules for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

When one container can't reach another, whyreach collects evidence from the right network namespaces (Docker metadata, listening sockets, DNS and TCP probes) and explains the cause, without changing anything.

```
$ whyreach --from container:shop-worker-1 api:8080
✗ worker → api:8080 — cause identified (high)

WR002  api listens only on 127.0.0.1:8080 inside its container
       …
  fix    Make the server in api listen on 0.0.0.0:8080 (or [::]:8080), …
```

`--from` takes `host`, `container:<name|id>` or `service:<name>[@<project>]`; add `--json` for machine-readable output. Exit codes: 0 no problem reproduced, 1 cause found, 2 inconclusive, 3 usage error, 4 internal error.

DNS and TCP checks from inside a container need **probe containers**, which are off by default because they write to Docker (a short-lived, hardened, labeled container, removed afterwards). Turn them on in `~/.config/whyreach/config.toml`:

```toml
[permissions]
probe_containers = true
```

Without them, whyreach still settles most causes from Docker metadata and the containers' listening sockets, and says what it could not check.

## Development

```bash
make build   # static binary in bin/whyreach
make test    # unit tests and rule fixtures (no Docker, no root)
make lint    # golangci-lint v2
make cross   # compile check for macOS and Windows
make lab     # the failure lab in test/lab (needs Docker)
```

## License

Apache-2.0. See [LICENSE](LICENSE).
