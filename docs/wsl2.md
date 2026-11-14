# whyreach on Windows, through WSL2

> **Status: built for v0.2, not yet validated.** whyreach claims WSL2 support only once the manual lab runs on Windows pass (`docs/wsl2-lab.md`). Until then, this page is the setup those runs check, and the README doesn't mention it.

whyreach is a Linux program. On Windows it runs inside a WSL2 distro, next to Docker, and an MCP client on Windows starts it there through `wsl.exe`. Two setups work, and whyreach tells them apart by itself (`whyreach doctor` prints which one it found):

| Setup | whyreach's name | Container checks | The host's side |
|---|---|---|---|
| Docker Engine installed in the distro | `wsl2-engine` | as on Linux: listening sockets read through `/proc` with no Docker write; DNS and TCP checks in probe containers (or, as root, by entering the containers' network namespaces) | the WSL2 VM, not Windows |
| Docker Desktop's WSL integration (WSL 2 backend, Linux containers) | `wsl2-desktop` | everything that looks inside a container (listening sockets, DNS, TCP) runs in probe containers: Docker Desktop's containers live in its own VM, whose processes whyreach can't see | the WSL2 VM, not Windows; the host containers reach through `host.docker.internal` is Windows, which whyreach can't check |

Windows containers aren't supported, and neither is a native Windows build (v0.3).

## Install

Inside the distro, follow the README's install steps for Linux (`linux_amd64` or `linux_arm64` archive, checksum, `~/.local/bin`). Then check it from the distro:

```bash
whyreach doctor
```

Its `platform` line names the setup, and its `mcp` line prints the exact `wsl.exe` command for this distro.

On `wsl2-desktop`, whyreach can't see inside containers without probe containers, so allow them in the config, or approve them when your client asks (only clients with elicitation can ask). The config lives in the distro, at `~/.config/whyreach/config.toml`:

```toml
[permissions]
probe_containers = true
```

## Connect a client on Windows

The command is the same for every client: `wsl.exe -d <distro> --exec <absolute path in the distro> mcp serve`. `--exec` starts whyreach without a shell, as the distro's default user, so use the absolute path (`~` and `$PATH` from your shell profile don't apply). Find it with `command -v whyreach` in the distro.

**Claude Code on Windows** (PowerShell):

```powershell
claude mcp add whyreach -- wsl.exe -d Ubuntu-24.04 --exec /home/you/.local/bin/whyreach mcp serve
```

**Claude Desktop, Cursor, and other clients with a JSON config** (`mcpServers`):

```json
{
  "mcpServers": {
    "whyreach": {
      "command": "wsl.exe",
      "args": ["-d", "Ubuntu-24.04", "--exec", "/home/you/.local/bin/whyreach", "mcp", "serve"]
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`, or the user configuration):

```json
{
  "servers": {
    "whyreach": {
      "type": "stdio",
      "command": "wsl.exe",
      "args": ["-d", "Ubuntu-24.04", "--exec", "/home/you/.local/bin/whyreach", "mcp", "serve"]
    }
  }
}
```

An agent that itself runs inside the distro (Claude Code installed in WSL, or VS Code's WSL remote) uses the Linux setup from the README instead: `claude mcp add whyreach -- /home/you/.local/bin/whyreach mcp serve`.

## Settings are flags

Environment variables in a Windows client's MCP configuration don't reach the distro, unless `WSLENV` lists them. So:

- permissions and probe settings go in the config file in the distro (above);
- the log level is a flag: add `--log-level info` (or `debug`) after `mcp serve`; logs go to the client's server log, never to the protocol;
- `DOCKER_HOST` isn't needed: both setups provide `/var/run/docker.sock` in the distro.

When the client closes, whyreach sees its input end and exits at once, so nothing stays running in the distro.

## What differs from Linux

- **The host is the WSL2 VM.** Host-side facts (the host's listening sockets, interfaces, connections from the host) describe the distro's VM, and whyreach says "the WSL2 VM" for them. A service on Windows itself isn't visible from WSL.
- **On `wsl2-desktop`, `host.docker.internal` is Windows.** Docker Desktop provides the name (WR011 never fires there), and a container reaching it reaches Windows. whyreach can't read Windows' listening sockets, so a question about a host service ends with a gap that says how to check on Windows (`Get-NetTCPConnection -State Listen -LocalPort <port>` in PowerShell). A service in the distro can be reachable that way only when WSL forwards its port to Windows (`localhostForwarding`, or mirrored networking).
- **On `wsl2-engine`, WSL stops idle distros**, about 15 seconds after the last process in it exits (`instanceIdleTimeout`), and `dockerd` with it: containers stop, and only those with a restart policy come back when the distro starts again. Keep a terminal open on the distro while you work, or set `instanceIdleTimeout=-1` under `[general]` in `%UserProfile%\.wslconfig` (then `wsl --shutdown` once). Docker itself recommends Docker Desktop over Docker Engine in WSL2. `doctor` warns about this.
- **On `wsl2-desktop`, probe containers do more work**: each container whose listening sockets a diagnosis needs is one short-lived probe container (at most 6 a diagnosis), and each counts against `rate_per_minute` (30 by default).

## Troubleshooting

- `wsl.exe -d Ubuntu-24.04 --exec /home/you/.local/bin/whyreach doctor`, from PowerShell, shows what the client's whyreach sees.
- `doctor`'s `docker` line fails: on `wsl2-engine`, start `dockerd` (`sudo systemctl start docker`) and check that your user is in the `docker` group; on `wsl2-desktop`, start Docker Desktop and turn its WSL integration on for the distro.
- The `platform` line says `linux-engine` in WSL: WSL's interop is off in `/etc/wsl.conf`, so whyreach can't confirm WSL2. Nothing unsafe follows; only the host's side is called "the host" instead of "the WSL2 VM".
