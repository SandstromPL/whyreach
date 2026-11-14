# The WSL2 lab runs (M6)

M6's exit criterion is that the lab passes inside WSL2 (`INITIAL.md` §7). These are the two manual runs on a Windows PC, one per setup:

| Run | Setup | Distro | whyreach's name for it |
|---|---|---|---|
| A | Docker Engine installed inside the distro | `Ubuntu-24.04` | `wsl2-engine` |
| B | Docker Desktop's WSL integration (WSL 2 backend, Linux containers) | `Debian` | `wsl2-desktop` |

This guide starts from a Windows PC where WSL isn't set up, or isn't set up well. Go in this order: the PC, once; then run A, steps 0 to 5; then run B, steps 0 to 5. Install Docker Desktop only when you reach run B. The first time takes about an hour and a half, mostly downloads and one restart; a re-run takes a few minutes. Why the lab expects what it expects on each setup: `docs/adr/0004-wsl2.md`, Decision 6.

Each run gets its own distro: Docker Engine and Docker Desktop's integration in one distro fight over `/var/run/docker.sock`. All WSL2 distros share one VM, so only one setup runs at a time (step 0).

**How to read the commands.** The line before each block says where it runs:

- **PowerShell:** Start → type `powershell` → Enter. **PowerShell (administrator):** right-click Windows PowerShell → Run as administrator.
- **Ubuntu** or **Debian:** a shell inside that distro. Open one from PowerShell with `wsl -d Ubuntu-24.04 --cd ~` or `wsl -d Debian --cd ~`.

Nothing needs filling in: the commands find your user names themselves. Every step says what it must print; if it prints something else, see Troubleshooting at the end. In a distro, run `sudo -v` on its own first and type your password, then paste each block whole (Windows Terminal may ask before pasting several lines: Paste anyway). Without `sudo -v`, the block's next line would go to sudo's password prompt.

## Before you leave the dev box

The code comes as a git bundle, since the WSL2 work isn't on GitHub until main is pushed. On the dev box, in the repository:

```bash
mkdir -p bin/wsl2
git bundle create bin/wsl2/whyreach-wsl2.bundle HEAD "$(git branch --show-current)"
(cd bin/wsl2 && sha256sum whyreach-wsl2.bundle > whyreach-wsl2.bundle.sha256)
cp docs/wsl2-lab.md bin/wsl2/
```

Copy the folder `bin/wsl2` (the bundle, its checksum and this guide) to a USB stick. The same stick brings the results back (step 8).

## The PC, once

### a. Check Windows

- Windows 11 23H2 or later, or Windows 10 22H2 (build 19045) or later: run `winver`. Docker Desktop needs these.
- Hardware virtualization: Task Manager → Performance → CPU must say `Virtualization: Enabled`. If it says Disabled, turn on Intel VT-x or AMD SVM in the PC's UEFI (BIOS) setup first.
- 8 GB of RAM, about 15 GB free on `C:`, an administrator account and an internet connection.

### b. WSL

**PowerShell (administrator):**

```powershell
wsl --update
wsl --install --no-distribution
```

Restart Windows. Then, in **PowerShell**:

```powershell
wsl --update
wsl --set-default-version 2
wsl --version
wsl --list --verbose
```

`wsl --version` must start with `WSL version: 2.` (2.1.5 or later). `wsl --list --verbose` shows the distros you already have; this guide leaves them alone. If `Ubuntu-24.04` or `Debian` is already there, see Troubleshooting.

### c. The files

**PowerShell:**

```powershell
New-Item -ItemType Directory -Force -Path C:\whyreach-lab | Out-Null
```

Copy the three files from the USB stick into `C:\whyreach-lab` (File Explorer is fine). Then `Get-ChildItem C:\whyreach-lab` must list `whyreach-wsl2.bundle`, `whyreach-wsl2.bundle.sha256` and `wsl2-lab.md`. Inside the distros the folder is `/mnt/c/whyreach-lab`, and the results go to `C:\whyreach-lab\results`.

## 0. Before each run

- **Run A:** Docker Desktop must not run. If it's installed, quit it (tray icon → Quit Docker Desktop). Then, in **PowerShell**: `wsl --shutdown`.
- **Run B:** in **PowerShell**, `wsl --shutdown`, which stops run A's Docker Engine. Then start Docker Desktop (the first time, step 1 installs it) and wait until it says Engine running. Don't open `Ubuntu-24.04` during run B: its Docker Engine would start next to Docker Desktop.

## 1. The distro

### Run A: Docker Engine in `Ubuntu-24.04`

**PowerShell:**

```powershell
wsl --install -d Ubuntu-24.04
```

It asks for a new user name and password (they belong to this distro only; sudo asks for the password), then leaves you in the Ubuntu shell.

**Ubuntu:** systemd must run, so that Docker starts with the distro.

```bash
ps -p 1 -o comm=
```

It must print `systemd` (new Ubuntu installs have it). If it prints `init`, turn systemd on with the line below, run `wsl --terminate Ubuntu-24.04` in PowerShell, reopen the distro and check again.

```bash
printf '[boot]\nsystemd=true\n' | sudo tee -a /etc/wsl.conf
```

**Ubuntu:** Docker Engine, from Docker's repository (Docker's own steps). Run `sudo -v` first.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```

The docker group counts from your next login. In **PowerShell**, `wsl --terminate Ubuntu-24.04`, then reopen the distro. In **Ubuntu**:

```bash
docker version --format '{{.Server.Platform.Name}}'
```

It must print `Docker Engine - Community`.

### Run B: Docker Desktop's integration in `Debian`

**PowerShell:**

```powershell
wsl --install -d Debian
```

Pick a user name and password, then type `exit` to get back to PowerShell. Make Debian the default distro: that's the one Docker Desktop integrates with when it first starts.

```powershell
wsl --set-default Debian
```

**Docker Desktop:**

1. Download Docker Desktop for Windows from <https://docs.docker.com/desktop/setup/install/windows-install/> (x86_64, or ARM64 on an ARM PC) and run `Docker Desktop Installer.exe`. Keep **Use WSL 2 instead of Hyper-V** selected. If it asks you to sign out or restart, do.
2. Start Docker Desktop from the Start menu. Accept the agreement (free for personal use and small businesses); skip signing in and the survey.
3. Settings (the gear) → Resources → WSL Integration: **Debian on, `Ubuntu-24.04` off** → Apply & restart. If WSL Integration isn't there, Docker Desktop is in Windows containers mode: tray icon → Switch to Linux containers.
4. Wait until Docker Desktop says Engine running.

**Debian:**

```bash
docker version --format '{{.Server.Platform.Name}}'
```

It must print `Docker Desktop` and a version. Don't install Docker Engine in this distro.

## 2. Go and the build tools (in this run's distro)

The repository builds with the Go toolchain `go.mod` pins (go1.27.4). This installs exactly that one, for your PC's architecture. Run `sudo -v` first.

```bash
cd ~
sudo apt-get update
sudo apt-get install -y ca-certificates curl git make procps
go_tgz="go1.27.4.linux-$(dpkg --print-architecture).tar.gz"
curl -fsSLO "https://go.dev/dl/$go_tgz"
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$go_tgz" && rm "$go_tgz"
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc && export PATH=/usr/local/go/bin:$PATH
go version
```

It must print `go version go1.27.4 linux/amd64` (or `linux/arm64`).

## 3. The code (in this run's distro)

```bash
cd /mnt/c/whyreach-lab && sha256sum -c whyreach-wsl2.bundle.sha256 && git clone whyreach-wsl2.bundle ~/whyreach && cd ~/whyreach && git log --oneline -1
```

It must print `whyreach-wsl2.bundle: OK`, then the commit the dev box bundled. The clone lives in the distro's own file system (`~/whyreach`), not under `/mnt/c`, where builds are slow and file modes don't hold. If main has been pushed with this guide, `git clone https://github.com/SandstromPL/whyreach ~/whyreach` works too; check that it has `test/wsl2/run-lab.sh`.

## 4. The lab (in this run's distro)

```bash
cd ~/whyreach && test/wsl2/run-lab.sh; mkdir -p "/mnt/c/whyreach-lab/results/$WSL_DISTRO_NAME" && cp -r bin/wsl2-lab/. "/mnt/c/whyreach-lab/results/$WSL_DISTRO_NAME/"
```

`run-lab.sh` checks the setup, builds whyreach, runs the unit tests (including the one that `mcp serve` exits when its input closes), prints `whyreach doctor`'s lines about the platform, runs the lab, and writes `bin/wsl2-lab/<time>/summary.txt`. The first run downloads Go modules and takes a few minutes; the lab itself takes about a minute. The lab prints the platform it found first: run A must say `wsl2-engine`, run B `wsl2-desktop`. The rest of the line copies the run's folder to `C:\whyreach-lab\results\<distro>`, even when the run stopped early. The summary has no user, host or home names; the full logs next to it may have them, so they go to the dev box only.

What passing means:

- **Run A:** every scenario passes with probe containers on and with the default config, as on a Linux host.
- **Run B:** with probe containers on, every scenario's usual expectation holds (containers' listening sockets come from probe containers, and the lab checks that none came from `/proc`). With the default config, containers can't be looked into at all, so each diagnosis must give the expected cause or a weaker verdict with a gap that says how to allow probe containers, never another cause. WR011's and WR012's scenarios have their own expectation there: Docker Desktop provides `host.docker.internal`, and the host it reaches is Windows.

## 5. The launch from Windows (in this run's distro, then PowerShell)

This is what an MCP client on Windows does: start whyreach through `wsl.exe`, talk to it over its input and output, then go away. In the distro, print this run's command:

```bash
l="powershell -NoProfile -ExecutionPolicy Bypass -File $(wslpath -w "$HOME/whyreach/test/wsl2/mcp-launch.ps1") -Distro $WSL_DISTRO_NAME -Whyreach $HOME/whyreach/bin/whyreach"; t="Tee-Object -FilePath C:\whyreach-lab\results\launch-$WSL_DISTRO_NAME.txt -Append"; echo "$l | $t; $l -Cold | $t"
```

Copy the line it prints, paste it into **PowerShell** and run it. It runs the check twice: first with the distro running, then from a cold start. `-Cold` stops the distro first, so `wsl.exe` has to boot it, as when a client starts whyreach after WSL stopped the idle distro (WSL stops a distro about 15 seconds after its last terminal or `wsl.exe` command closes). Stopping it also closes the distro's open terminals.

Each run must end in `PASS`: whyreach answered (the `initialize` line says how many ms after the start), listed its four tools, reported a WSL2 platform (`wsl2-engine` in run A, `wsl2-desktop` in run B), exited within 5 s of its input closing, and left no whyreach server of its own running in the distro (one started by another MCP client there doesn't count). Both outputs go to `C:\whyreach-lab\results\launch-<distro>.txt`.

## 6. Optional: the netns executor in run A

As root, whyreach enters containers' network namespaces itself on `wsl2-engine` (not on `wsl2-desktop`, by design). With run A's setup running (step 0), in **Ubuntu**:

```bash
cd ~/whyreach && make lab-root 2>&1 | tee /mnt/c/whyreach-lab/results/lab-root.txt
```

It asks for your sudo password once and runs every scenario through the netns executor. If WSL's root lacks the privilege (`sudo bin/whyreach doctor` says so on its `netns executor` line), that's worth knowing too.

## 7. Optional: a real client

To try a client on Windows, follow `docs/wsl2.md` (install whyreach in the distro, add it to Claude Code, Claude Desktop, VS Code or Cursor with the `wsl.exe` command), start the demo in the distro (`docker compose -f demo/compose.yaml up -d --wait`), and ask the agent why `worker` can't reach `http://localhost:8080`. It should answer WR007, with `api:8080` as the fix (with probe containers off, on run B, it says it can't see inside the containers and asks for them).

## 8. Bring the results back

`C:\whyreach-lab\results` now holds a folder per distro (each run's `summary.txt` and logs), the two `launch-*.txt` files, and `lab-root.txt` if you ran step 6. Glance over the summaries and the launch outputs: they should hold versions, test names and whyreach's findings, nothing about your machine. Copy the `results` folder to the USB stick and, back on the dev box, to `bin/wsl2/results` in the repository (git ignores `bin/`). Add what the client did, if you ran step 7.

Keep both distros until the results are read: a fix means a re-run with a new bundle.

## Re-running with a new bundle

Put the new bundle and its checksum in `C:\whyreach-lab`. Then, for each run, step 0, this in the distro, and steps 3 to 5 again (Go and Docker stay installed):

```bash
rm -rf ~/whyreach
```

## Troubleshooting

| What you see | What to do |
|---|---|
| `wsl --install` prints help text | WSL is already there: `wsl --update`, then the same `wsl --install -d …` line again. |
| `wsl --version` prints help text or "invalid command line option" | That's the old WSL built into Windows 10: `wsl --update` in PowerShell (administrator), restart, try again. |
| Error `0x80370102`, or a message to enable the Virtual Machine Platform and virtualization in the BIOS | Turn on virtualization in the UEFI setup, run `wsl --install --no-distribution` in PowerShell (administrator), restart. |
| A distro install stays at 0.0% | `wsl --install --web-download -d Ubuntu-24.04` (or `Debian`). |
| `wsl --list --verbose` shows `VERSION 1` for the distro | `wsl --set-version Ubuntu-24.04 2` (or `Debian`). |
| `Ubuntu-24.04` or `Debian` is already there from an earlier try | Use it if its steps pass. Otherwise `wsl --unregister Ubuntu-24.04` (or `Debian`) deletes it, with everything in it, and step 1 installs it again. |
| Ubuntu: `permission denied` on `/var/run/docker.sock` | The docker group isn't active yet: `wsl --terminate Ubuntu-24.04` in PowerShell, then reopen the distro. |
| Ubuntu: `Cannot connect to the Docker daemon` | `ps -p 1 -o comm=` must print `systemd` (step 1); then `sudo systemctl start docker`. |
| Ubuntu: `docker version` names Docker Desktop | Docker Desktop's integration is on for Ubuntu: turn it off (Settings → Resources → WSL Integration), quit Docker Desktop, `wsl --shutdown`. |
| Debian: "The command 'docker' could not be found in this WSL 2 distro" | Docker Desktop isn't running, or its integration for Debian is off (step 1). |
| `apt-get` or `curl` can't resolve names | `wsl --shutdown` in PowerShell and try again; with a VPN on, try without it. |
| `sha256sum -c` prints `FAILED` | The copy is incomplete: copy the bundle from the stick again. |
| `git clone` says the destination already exists | There's an earlier clone: `rm -rf ~/whyreach`, then step 3 again. |
| `run-lab.sh` prints `STOPPED: …` | The line says what's missing and which step installs it. |
| PowerShell: "running scripts is disabled on this system" | The line from step 5 passes `-ExecutionPolicy Bypass`; check that it was pasted whole. |
