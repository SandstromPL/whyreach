# The WSL2 lab runs (M6)

M6's exit criterion is that the lab passes inside WSL2 (`INITIAL.md` §7). These are the two manual runs on a Windows PC, one per setup:

| Run | Setup | whyreach's name for it |
|---|---|---|
| A | Docker Engine installed inside a WSL2 distro | `wsl2-engine` |
| B | Docker Desktop's WSL integration (WSL 2 backend, Linux containers) | `wsl2-desktop` |

Each run takes about 15 minutes the first time (installing), then about 2 minutes. Every step below is copy and paste; `<you>` is your Windows user name, and the distro names are only suggestions. Why the lab expects what it expects on each setup: `docs/adr/0004-wsl2.md`, Decision 6.

Use **two distros**, one per run: Docker Engine and Docker Desktop's integration in one distro fight over `/var/run/docker.sock`. Run them one at a time (step 0 says how), since all WSL2 distros share one VM.

## 0. Before each run

In PowerShell, stop the other setup:

- Before run A: quit Docker Desktop (tray icon → Quit Docker Desktop), or at least turn its WSL integration off for distro A (Settings → Resources → WSL integration).
- Before run B: `wsl --terminate Ubuntu-24.04` (distro A), so its `dockerd` isn't running next to Docker Desktop.

## 1. The distros

### Run A: Docker Engine in `Ubuntu-24.04`

In PowerShell (if WSL itself isn't installed yet, the first `wsl --install` needs PowerShell run as administrator, and Windows may ask for a reboot before the distro starts):

```powershell
wsl --install -d Ubuntu-24.04
```

Then, inside the distro (it opens after the install; later: `wsl -d Ubuntu-24.04`), install Docker Engine from Docker's repository:

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git make
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker "$USER"
grep -A1 '^\[boot\]' /etc/wsl.conf
```

The last line must print `systemd=true` (new Ubuntu installs have it), so that `dockerd` starts with the distro. If it doesn't, add it: `printf '[boot]\nsystemd=true\n' | sudo tee -a /etc/wsl.conf`. Then, in PowerShell, restart the distro so the group and systemd take effect:

```powershell
wsl --terminate Ubuntu-24.04
```

Back inside (`wsl -d Ubuntu-24.04`), `docker version` must print `Server: Docker Engine - Community`.

### Run B: Docker Desktop's integration in `Debian`

Docker Desktop for Windows must use the WSL 2 based engine (Settings → General) and Linux containers (the default). In PowerShell:

```powershell
wsl --install -d Debian
```

In Docker Desktop: Settings → Resources → WSL integration → turn it on for **Debian** only → Apply & restart. Inside the distro (`wsl -d Debian`):

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git make
docker version
```

`docker version` must print `Server: Docker Desktop …`. Don't install Docker Engine in this distro.

## 2. Go (in each distro)

The repository builds with the Go toolchain `go.mod` pins (go1.27.4). Install exactly that one; `dpkg --print-architecture` picks the build for your PC (amd64 or arm64):

```bash
go_tgz="go1.27.4.linux-$(dpkg --print-architecture).tar.gz"
curl -fsSLO "https://go.dev/dl/$go_tgz"
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$go_tgz" && rm "$go_tgz"
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc && export PATH=/usr/local/go/bin:$PATH
go version
```

## 3. The code (in each distro)

The WSL2 work isn't on GitHub until the owner pushes it, so it comes as a git bundle: `bin/wsl2/whyreach-wsl2.bundle` in the dev box's worktree, with its SHA-256 next to it. Copy it to the PC's `Downloads` folder, then inside each distro:

```bash
sha256sum /mnt/c/Users/<you>/Downloads/whyreach-wsl2.bundle
git clone -b claude/v0-2-wsl2-d95b8c /mnt/c/Users/<you>/Downloads/whyreach-wsl2.bundle ~/whyreach
cd ~/whyreach && git log --oneline -1
```

The checksum must match the one shipped with the bundle. If the branch has been pushed instead, clone it from GitHub with the same `-b`. Keep the clone in the distro's own file system (`~/whyreach`), not under `/mnt/c`: builds there are slow and file modes don't hold.

## 4. The lab (in each distro, after step 0)

```bash
cd ~/whyreach && test/wsl2/run-lab.sh
```

It checks the setup, builds whyreach, runs the unit tests (including the one that `mcp serve` exits when its input closes), prints `whyreach doctor`'s lines about the platform, runs the lab (about a minute), and writes `bin/wsl2-lab/<time>/summary.txt`. The summary has no user, host or home names; the full logs are next to it. The lab prints the platform it found first: run A must say `wsl2-engine`, run B `wsl2-desktop`.

What passing means:

- **Run A:** every scenario passes with probe containers on and with the default config, as on a Linux host.
- **Run B:** with probe containers on, every scenario's usual expectation holds (containers' listening sockets come from probe containers, and the lab checks that none came from `/proc`). With the default config, containers can't be looked into at all, so each diagnosis must give the expected cause or a weaker verdict with a gap that says how to allow probe containers, never another cause. WR011's and WR012's scenarios have their own expectation there: Docker Desktop provides `host.docker.internal`, and the host it reaches is Windows.

## 5. The launch from Windows (once per distro)

This is what an MCP client on Windows does: start whyreach through `wsl.exe`, talk to it over its input and output, then go away. In PowerShell, run the script straight from the distro's copy of the repository (`<distro user>` is your user name inside the distro):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu-24.04\home\<distro user>\whyreach\test\wsl2\mcp-launch.ps1 -Distro Ubuntu-24.04 -Whyreach /home/<distro user>/whyreach/bin/whyreach
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File \\wsl.localhost\Debian\home\<distro user>\whyreach\test\wsl2\mcp-launch.ps1 -Distro Debian -Whyreach /home/<distro user>/whyreach/bin/whyreach
```

Run each after step 4 in that distro (which built `bin/whyreach`), with that distro's setup running (step 0). Each must end in `PASS`: whyreach answered, listed its four tools, reported its platform, exited within 5 s of its input closing, and left no whyreach server of its own running in the distro (one started by another MCP client there doesn't count).

## 6. Optional: the netns executor in run A

As root, whyreach enters containers' network namespaces itself on `wsl2-engine` (not on `wsl2-desktop`, by design). In distro A:

```bash
cd ~/whyreach && make lab-root
```

It asks for your sudo password once and runs every scenario through the netns executor. If WSL's root lacks the privilege (`doctor` says so on its `netns executor` line when run with sudo), that's worth knowing too.

## 7. Optional: a real client

To try a client on Windows, follow `docs/wsl2.md` (install whyreach in the distro, add it to Claude Code, Claude Desktop, VS Code or Cursor with the `wsl.exe` command), start the demo in the distro (`docker compose -f demo/compose.yaml up -d --wait`), and ask the agent why `worker` can't reach `http://localhost:8080`. It should answer WR007, with `api:8080` as the fix (with probe containers off, on run B, it says it can't see inside the containers and asks for them).

## 8. Send back

- Both `summary.txt` files (step 4).
- Both outputs of `mcp-launch.ps1` (step 5).
- Optional: `make lab-root`'s last lines (step 6), and what the client did (step 7).

Glance over them before sending: they should hold versions, test names and whyreach's findings, nothing about your machine. Afterwards, `docker compose ls` shows no `whyreach-lab-*` project; the lab removes its own containers, networks and images.
