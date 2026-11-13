# whyreach

**Why can't one container reach another?** whyreach answers that with evidence, without changing anything. It runs as a CLI and as an MCP server for AI coding agents.

When a service gets `Connection refused`, a timeout or a name that doesn't resolve, whyreach collects evidence from the right network namespaces: Docker metadata, the listening sockets inside each container, DNS as the source container sees it, and a TCP connect from the source. Then it names the cause from a catalog of 14 rules, such as `localhost` used inside a container, a server bound to `127.0.0.1`, or two Compose projects that share no network. Each finding comes with the evidence behind it and a fix.

```
$ whyreach --from service:worker@whyreach-demo localhost:8080
✗ worker → localhost:8080 — cause identified (high)

WR007  localhost inside worker is worker itself, not api
       Inside a container, localhost is the container's own network namespace,
       not the host's or another container's. Nothing in worker listens on
       port 8080, while api (listening on 0.0.0.0:8080 in api, network
       whyreach-demo_default) does.
  facts  • listening on port 8080 in api: 0.0.0.0:8080/tcp  [ev-06]
         • nothing listens on port 8080 in worker           [ev-07]
  fix    Connect to api:8080 instead of localhost:8080: the Compose service
         name resolves on the shared network.
  …
```

> **Status: v0.1.** Linux with Docker Engine only. Docker Desktop, macOS and Windows come later ([INITIAL.md §3.7](INITIAL.md)).

## Install

You need Linux on amd64 or arm64, Docker Engine, and access to the Docker socket (your user in the `docker` group). whyreach is one static binary.

Download the archive for your machine and `checksums.txt` from the [releases page](https://github.com/SandstromPL/whyreach/releases), check the checksum, and put the binary on your `PATH`:

```bash
VERSION=0.1.0 ARCH=amd64   # or ARCH=arm64; uname -m says x86_64 for amd64, aarch64 for arm64
curl -fsSLO "https://github.com/SandstromPL/whyreach/releases/download/v${VERSION}/whyreach_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "https://github.com/SandstromPL/whyreach/releases/download/v${VERSION}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
mkdir whyreach && tar -xzf "whyreach_${VERSION}_linux_${ARCH}.tar.gz" -C whyreach
install -D -m 0755 whyreach/whyreach ~/.local/bin/whyreach
```

The archive holds the binary, this README, the license, and the demo (`demo/compose.yaml`). If `~/.local/bin` isn't on your `PATH`, install to `/usr/local/bin` with `sudo` instead. Each release also has a signed build-provenance attestation, which [`gh`](https://cli.github.com/) can check: `gh attestation verify whyreach_${VERSION}_linux_${ARCH}.tar.gz --repo SandstromPL/whyreach`.

Then check that whyreach can do its job here:

```bash
whyreach doctor
```

It checks the Docker API, the listening sockets it can read, and its config, and it tells you what it can't do and why. It changes nothing. Its `mcp` line gives the command that connects whyreach to Claude Code.

To build from source instead, use Go 1.27 or later and run `make build`, which writes `bin/whyreach`.

## Connect your AI agent (MCP)

whyreach serves four tools over stdio: `diagnose_connection`, `inspect_environment`, `run_probe` and `save_report`. Give your MCP client the binary's absolute path and the arguments `mcp serve`.

**Claude Code:**

```bash
claude mcp add whyreach -- "$HOME/.local/bin/whyreach" mcp serve
```

This adds whyreach to the current project. Add `--scope user` to make it available in every project.

**Other clients** (Cursor, Windsurf, Claude Desktop and most others) take a JSON entry like this one, in their MCP settings file (for Cursor, `~/.cursor/mcp.json`). Use the absolute path, without `~`:

```json
{
  "mcpServers": {
    "whyreach": {
      "command": "/home/you/.local/bin/whyreach",
      "args": ["mcp", "serve"]
    }
  }
}
```

VS Code's `.vscode/mcp.json` uses the same entry under `"servers"` instead of `"mcpServers"`. Codex reads `~/.codex/config.toml`:

```toml
[mcp_servers.whyreach]
command = "/home/you/.local/bin/whyreach"
args = ["mcp", "serve"]
```

Run the MCP server as your own user, not as root. Each tool returns a short structured result that starts with the verdict, plus a text summary. Every call is recorded in `~/.local/state/whyreach/audit.jsonl`.

## Try it: the demo

The demo is a small Compose project with the most common Docker networking mistake. A worker calls an API at `http://localhost:8080/`. Inside the worker's container, though, `localhost` is the worker itself, and the API runs in a container of its own.

The demo file is `demo/compose.yaml`, in the release archive and in this repository. Start it from the directory that holds `demo/`. The first run pulls `python:3.13-slim`.

```bash
docker compose -f demo/compose.yaml up -d --wait
docker compose -f demo/compose.yaml logs worker
```

The worker keeps failing:

```
worker: can't reach http://localhost:8080/ - <urlopen error [Errno 111] Connection refused>
```

Ask your agent about it, for example:

> In the Compose project whyreach-demo, the worker can't connect to http://localhost:8080. Use whyreach to find out why.

The agent calls `diagnose_connection` with `from: service:worker@whyreach-demo` and `to: localhost:8080`. whyreach answers with rule **WR007** at high confidence: `localhost` inside the worker means the worker, and the service is `api:8080`. You can ask the same from the CLI:

```bash
whyreach --from service:worker@whyreach-demo localhost:8080
```

To fix the demo, set `API_URL: http://api:8080/` in `demo/compose.yaml` and run the `up` command again. The worker's log then says `worker: reached http://api:8080/`. When you're done, remove the demo:

```bash
docker compose -f demo/compose.yaml down
```

whyreach settled this cause from Docker's metadata and the containers' listening sockets alone, without starting anything. Some causes also need a check from inside the source container, which needs a probe container (see the next section).

## What whyreach may do

whyreach is read-only. It never changes containers, networks, routes, firewall rules, DNS or files, apart from its own config, state and data directories. It reads Docker's API through an allowlist of endpoints, reads listening sockets from `/proc`, and makes bounded DNS lookups and TCP connects. A connect closes at once and never sends data. Docker socket access is equivalent to root, so this guarantee comes from whyreach's own code, not from operating-system permissions.

Some checks need permissions that are off by default. These are your decisions. An agent can't turn them on, and an agent that can edit files shouldn't change whyreach's config to give itself more.

- **Probe containers.** These run DNS and TCP checks from inside a container. whyreach imports its own binary as the local image `whyreach-probe` (no registry pull) and runs each batch of checks in a short-lived, locked-down container. The container joins the checked container's network namespace, carries the label `io.whyreach.probe=1`, and is removed afterwards. They are off by default because they write to Docker. Through MCP, whyreach asks you once per session when a probe container would change the answer, if your client supports elicitation. To allow them for good, set `probe_containers = true`.
- **Names outside Docker.** A DNS lookup sends its name to the servers of the name's domain, so through MCP an agent could pass data out through the names it asks whyreach to look up. Some names are always free: names that Docker's metadata knows (containers, Compose services, aliases), names in the source's hosts file, names without a dot, `localhost`, and `host.docker.internal`. Any other name, such as `example.com`, is looked up only after you approve that exact name when whyreach asks (at most three questions a session; approve only names you expect), or when its domain is listed under `[probe] names`. Without an approval nothing is sent, and the diagnosis says what it couldn't check. The CLI looks up any name you type.
- **Root.** Run as root (`sudo whyreach …`), whyreach enters containers' network namespaces itself and needs no probe containers. It then reads root's config and writes root's audit log. Use `sudo`, not `sudo -E`, and use root for the CLI only.

TCP probes may go only to the address classes in `[probe] allow`, at most `rate_per_minute` checks a minute. whyreach never contacts link-local or cloud-metadata addresses, nameservers included: where the first nameserver is one, as on some cloud VMs, it makes no lookup through it, and `whyreach doctor` warns.

Settings live in `~/.config/whyreach/config.toml`. Every key is optional; an unknown key is an error:

```toml
[permissions]
probe_containers = false   # true: allow probe containers (tier 2b)
netns = true               # false: as root, don't enter network namespaces

[probe]
allow = ["loopback", "rfc1918", "docker"]   # where TCP probes may go; also CIDRs
rate_per_minute = 30
names = []                 # domains an agent may have looked up without asking, e.g. ["example.com"]

[timeouts]
diagnosis = "15s"

[report]
redact_private = false     # true: exported reports also hide private addresses
```

Headless agent runs (`claude -p`, CI) can't answer a question. Turn on what they need in this file.

## The CLI

```
whyreach [--from SOURCE] HOST:PORT [--json] [--report]   # short for whyreach diagnose
whyreach inspect host | container NAME | service NAME[@PROJECT] | network NAME
whyreach probe tcp HOST:PORT | dns NAME | listeners [--from SOURCE]
whyreach report list | show ID | export ID [--redact-private]
whyreach rules list | explain WRxxx
whyreach doctor
whyreach mcp serve
```

`SOURCE` is `host` (the default), `container:<name|id>` or `service:<name>[@<project>]`. `HOST:PORT` is the destination as your app uses it: a Compose service, container name, alias, DNS name, IP address, `localhost` or `host.docker.internal`. Exit codes: 0 no problem reproduced, 1 cause or likely cause found, 2 inconclusive, 3 usage or policy error, 4 internal error.

**Reports.** `--report` saves the diagnosis with all its evidence as a bundle in `~/.local/share/whyreach/reports/`. The bundle holds a manifest, the diagnosis, the evidence and a Markdown report, and it isn't redacted: it's your own record. To share one, for example in an issue, run `whyreach report export ID`. It writes a redacted copy, `ID.tar.gz`, next to the bundle. Public addresses, host names and container IDs become pseudonyms, and your home directory becomes `~`. Private addresses are hidden too with `--redact-private`. Check the copy before you share it. Bundles saved through MCP (`save_report`) are always redacted.

**Rules.** `whyreach rules list` shows the 14 rules, and `whyreach rules explain WR007` prints a rule's page: the pitfall, the evidence, the fix and the known false positives. The same pages are in [docs/rules](docs/rules).

## As a container

There's an image too, for when you'd rather not install the binary:

```bash
docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/sandstrompl/whyreach:0.1.0 mcp serve
```

For Claude Code: `claude mcp add whyreach -- docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/sandstrompl/whyreach:0.1.0 mcp serve`. Pass a command instead of `mcp serve` to use the CLI the same way.

- **`--network host`** puts whyreach in the host's network namespace, where it sees the host's interfaces, listening sockets and connections. Without it, the host's side can't be seen from the container, and whyreach reports those checks as unsupported rather than mistake the container for the host.
- **`--pid host`** lets whyreach read the containers' listening sockets. Without it, whyreach reports those reads as unsupported, and causes that depend on listeners drop to lower confidence.
- To see which of the two whyreach has, run your command with `doctor` in place of `mcp serve`.
- **Your config:** mount it with `-v ~/.config/whyreach:/config/whyreach:ro`.
- **Audit log and reports:** they stay in the container unless you mount `/state` and `/data`.

## Development

The design is in [INITIAL.md](INITIAL.md), and the rules for contributors and coding agents are in [CLAUDE.md](CLAUDE.md).

```bash
make build      # static binary in bin/whyreach
make test       # unit tests and rule fixtures (no Docker, no root, no network)
make lint       # golangci-lint v2
make cross      # compile check for macOS and Windows
make lab        # the failure lab in test/lab (needs Docker)
make lab-root   # the same lab as root, where whyreach enters network namespaces itself (asks for your sudo password)
make lab-agent  # a headless agent diagnoses each lab scenario through MCP (needs the claude CLI)
make release-snapshot  # the release archives and checksums in dist/, publishing nothing
```

## License

Apache-2.0. See [LICENSE](LICENSE).
