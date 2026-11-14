# Contributing to whyreach

Thanks for helping. whyreach is small on purpose: it answers one question, "why can't this container reach that one?", safely and with proof. This page explains how to set up, test and send a change.

## Before you start

- **Open an issue first** for anything bigger than a small fix: a new rule, a new platform, a new MCP tool, or a change to how whyreach behaves.
- **Supported today:** Linux with Docker Engine. Windows through WSL2, and Docker Desktop on macOS and Windows, are on the roadmap ([INITIAL.md §3.7](INITIAL.md)). Keep code portable anyway.
- **Out of scope:** Kubernetes, eBPF, packet capture, parsing firewall rules, TLS and HTTP checks, fixing problems for the user, telemetry, and any LLM call inside whyreach.
- **The design** is in [INITIAL.md](INITIAL.md), and the decisions behind it are in [docs/adr](docs/adr). If your change and INITIAL.md disagree, update one of them in the same pull request.

## Set up

You need:

- Linux (amd64 or arm64) with Docker Engine, and your user in the `docker` group.
- Go 1.21 or newer. `go.mod` pins the toolchain (Go 1.27.4), and the `go` command downloads it for you.
- [golangci-lint](https://golangci-lint.run/) v2. CI uses v2.15.0.
- Only for the agent tests: the `claude` CLI. The benchmark also needs `bwrap`.

```bash
git clone https://github.com/SandstromPL/whyreach
cd whyreach
make build test
```

## Build and test

| Command | What it does | What it needs |
|---|---|---|
| `make build` | Builds the static binary in `bin/whyreach` | Go |
| `make test` | Unit tests and rule fixtures | Nothing more: no Docker, root or network |
| `make lint` | golangci-lint | golangci-lint v2 |
| `make vuln` | Checks for known vulnerabilities in the code whyreach calls | Network |
| `make cross` | Checks that the code compiles for macOS and Windows | Go |
| `make lab` | Runs every scenario in `test/lab`, with probe containers on and off | Docker. It creates and removes `whyreach-lab-*` resources only |
| `make lab-desktop` | The same lab with whyreach told it talks to Docker Desktop, so it reads every listener in a probe container | Docker. A rehearsal of the Docker Desktop path on Docker Engine |
| `make lab-root` | The same lab as root, through the containers' network namespaces | sudo (it asks). Only the test binaries run as root |
| `make lab-agent` | A headless agent diagnoses each scenario through whyreach's MCP tools | Docker and the `claude` CLI. A few cents a run on Claude Haiku |
| `make lab-bench` | The [agent benchmark](docs/research/agent-benchmark.md) | Docker, `claude` and `bwrap`. About 11 minutes and $0.08 |
| `make golden` | Refreshes the golden files after an intended change in output | Go |
| `make release-snapshot` | Builds the release archives in `dist/`, publishing nothing | Network (it downloads goreleaser) |

The README's demo GIF and benchmark chart are generated. When the CLI's text output changes, run `make build` and then `python3 docs/assets/make_demo_gif.py` (it needs Docker and Pillow, and runs the demo). After a new recorded benchmark run, run `python3 docs/assets/make_benchmark_chart.py`.

CI runs `make test`, `make cross`, `make build`, the linter and `make vuln` on every pull request. It doesn't run the lab, so run `make lab` yourself when you change behaviour, and say so in the pull request.

To run one rule's fixtures or one lab scenario:

```bash
go test ./internal/rules -run 'TestFixtures/WR002' -v
```

```bash
go test -tags lab -count=1 ./test/e2e -run 'TestLab/wr002' -v
```

## The safety rules

Every change must keep these promises. They are why whyreach is safe to run on a machine you care about, and safe to give to an AI agent.

1. **Read-only.** Never change routes, firewall rules, interfaces, DNS, containers, networks, or files outside whyreach's own config, state and data directories. The only Docker writes allowed are the optional probe image and probe container. They run only when the user allows them, carry the label `io.whyreach.probe=1`, and are reported in `side_effects`.
2. **No shell.** Product code never runs `sh -c`, and never shells out to `ip`, `ss`, `dig` or similar tools. Use netlink, `/proc`, the Docker API and Go's dialers. Tests and lab scripts may use CLI tools.
3. **Arguments narrow permissions, never widen them.** Permissions come from the user's config or from their answer to a question in the MCP client, never from a tool argument.
4. **Bounded probes.**
   - One host:port per call; no ranges, lists, CIDRs or wildcards.
   - Never link-local or cloud-metadata addresses.
   - Rate-limited.
   - Connect, then close, with no payload.
   - Through MCP, looking up outside names and connecting to private addresses outside Docker's networks need the user's approval.
5. **stdout belongs to MCP** in `whyreach mcp serve`. Log to stderr with `log/slog`.
6. **No secrets.** Evidence never includes environment variable values, or file contents other than `resolv.conf` and `hosts`. Never read the credential entries of `~/.docker/config.json`.
7. **Every check has a timeout and an explicit status.** Missing evidence is a gap, never a negative result.
8. **No telemetry and no update checks.**

Diagnoses follow a few more rules:

- **Facts and findings stay apart.** Facts are what was observed, with evidence IDs. Findings are hypotheses with a confidence (high, medium or low), and each one cites the evidence behind it.
- **Every address names its context**, as in "127.0.0.1 in api": `localhost` means something different in each container.
- **Refused, timeout and unreachable are different results.** Keep the errno.
- **Output is deterministic.** Sort everything.
- **Rule IDs (`WRxxx`) are permanent.** Never renumber or reuse one.

## Adding a rule

1. Implement it in `internal/rules/wrxxx_<slug>.go`. Give it a layer from the precedence table, and declare `Supersedes()` if it makes another rule redundant ([ADR 0002](docs/adr/0002-rule-order.md)).
2. Add fixtures in `internal/rules/testdata/WRxxx/`: at least one case where the rule fires and one where it must not.
3. Add a lab scenario in `test/lab/wrxxx-<slug>/` (`compose.yaml` and `scenario.yaml`), with expectations for probe containers on and off. Comments may explain the scenario, since agents get the Compose files without them, but no setting (a service, network or container name, a label) may name the scenario or a rule. `make test` checks.
4. Write `docs/rules/WRxxx.md`: the pitfall, the evidence, the fix, and the known false positives.
5. Add the rule to the catalog in [INITIAL.md §4.6](INITIAL.md).

## Code

- `CGO_ENABLED=0`: the binary must stay static.
- `context.Context` is the first parameter of anything that does I/O.
- Wrap errors with `%w`, and check them with `errors.Is` and `errors.As`.
- No global mutable state and no `init()` side effects.
- Write table-driven tests with `go-cmp`. Golden files live in `testdata/` and are refreshed with `make golden`.
- Add dependencies only with a good reason, given in the pull request. The current list is in [CLAUDE.md](CLAUDE.md).
- The MCP server has four tools, and the default answer to a fifth is no. Open an issue first.

## Test data and privacy

- **Use made-up values only.** Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and names under `example.com` or `.test`.
- **Clean real output first.** Never paste output from your own machine into a fixture or an issue without removing your addresses, host name, user name, DNS servers and MAC addresses.
- **Keep fake secrets obviously fake.** The repository is scanned for secrets.

## Commits and pull requests

- Keep commits small, with a message that says what changed and why.
- Before opening a pull request, run `make build test lint`. If behaviour changed, run `make lab` too.
- Fill in the pull request template. It asks what you ran.

## Using AI tools

AI coding tools are welcome; whyreach itself is built with them. These rules keep the quality up:

- **You own the change.** Read and understand every line before you open a pull request, and be ready to explain it in review.
- **Test it for real.** Run the same checks as for any change: `make build test lint`, and `make lab` when behaviour changes. AI tools are confident about code they never ran.
- **Say so.** If an AI tool wrote a meaningful part of the change, mention it in the pull request. An `Assisted-by:` or `Co-Authored-By:` line in the commit message works too.
- **Point your agent at [CLAUDE.md](CLAUDE.md).** It holds the project's rules for coding agents: the safety rules, the architecture and the conventions. Claude Code reads it automatically; give it to other agents in their instructions.
- **Keep private data out of AI tools.** Don't paste unredacted reports, or raw output from your machine, into an AI chat or agent. Use `whyreach report export` and check the copy first.
- **No careless bulk changes.** Pull requests and issues that look generated without review, such as large rewrites nobody asked for, made-up APIs or invented problems, will be closed.
- **Security reports need proof.** If an AI tool found a possible vulnerability, confirm it yourself and include a working reproduction before you report it.
- **Licensing still applies.** Submit only code you have the right to contribute under Apache-2.0, and don't let a tool copy in code from other projects.

## Reporting a bug

Use the bug report form. The most useful thing to attach is a redacted report:

1. Run the failing diagnosis again with `--report`.
2. Find its ID with `whyreach report list`.
3. Run `whyreach report export ID`. It writes a redacted copy, `ID.tar.gz`. Add `--redact-private` to hide private addresses too.
4. Check the copy before you attach it.

## Security

Report vulnerabilities privately, not in an issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE), like the rest of the project.
