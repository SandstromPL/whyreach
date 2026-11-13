# NetDoctor

Read-only network diagnosis for Linux and Docker, built for developers and their AI coding agents. It runs as a CLI and as an MCP server.

> **Status: pre-alpha (milestone M0).** Nothing usable yet. The design is in [INITIAL.md](INITIAL.md), and the rules for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

What it will do: when one container can't reach another, NetDoctor collects evidence from the right network namespaces (listeners, DNS, TCP probes, Docker metadata) and explains the cause, without changing anything.

```
$ netdoctor diagnose --from container:worker api:8080
✗ worker → api:8080 — cause identified (high)
ND002  api listens only on 127.0.0.1:8080 inside its container
```

## Development

```bash
make build   # static binary in bin/netdoctor
make test    # unit tests (no Docker, no root)
make lint    # golangci-lint v2
make cross   # compile check for macOS and Windows
```

## License

Apache-2.0. See [LICENSE](LICENSE).
