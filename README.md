# whyreach

Read-only network diagnosis for Linux and Docker, built for developers and their AI coding agents. It runs as a CLI and as an MCP server.

> **Status: pre-alpha.** M0 (scaffold and spikes) is done, and M1, the first vertical slice, is next. Nothing usable yet. The design is in [INITIAL.md](INITIAL.md), and the rules for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

What it will do: when one container can't reach another, whyreach collects evidence from the right network namespaces (listeners, DNS, TCP probes, Docker metadata) and explains the cause, without changing anything.

```
$ whyreach --from container:worker api:8080
✗ worker → api:8080 — cause identified (high)
WR002  api listens only on 127.0.0.1:8080 inside its container
```

## Development

```bash
make build   # static binary in bin/whyreach
make test    # unit tests (no Docker, no root)
make lint    # golangci-lint v2
make cross   # compile check for macOS and Windows
```

## License

Apache-2.0. See [LICENSE](LICENSE).
