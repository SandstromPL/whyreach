# Real cases

Broken Docker setups from Stack Overflow, the Docker Community Forums and GitHub issues, rebuilt here so whyreach can diagnose them: the real-case check in `docs/research/real-cases.md`. Each case is a folder named after its source (`so-<question>`, `forum-<topic>`, `gh-<owner>-<repo>-<issue>`) holding `case.yaml` and one or more Compose files. `make lab-realcases` runs them.

## Sources and licence

Every case links the question or issue it was rebuilt from and names its author. Compose files and commands adapted from Stack Overflow are under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), as Stack Overflow publishes them; the rest of this repository's licence doesn't apply to them. Text from the Docker Community Forums and GitHub issues stays its authors'; only the setup is rebuilt, with a link back.

## How a case is rebuilt

A case is rebuilt from the question alone, as the asker set it up, broken. The aim is the asker's failure, not a working setup.

- **Images.** Only these official images, at these tags, as they ship: `postgres:17`, `mysql:8.4`, `redis:7-alpine`, `nginx:stable-alpine`, `node:22-alpine` and `python:3.13-slim`, whatever version the question used. No `build:`, and no package installs (`pip`, `npm`, `apt`) at build or start. Anything else runs the lab's stand-in (below).
- **When to use a real image.** When the server's own defaults could matter (where it listens, how it starts), use its real image with the question's settings (environment, command, config passed on the command line). An app the asker wrote, or a framework that isn't in those images (Flask, Express, Spring), becomes either the stand-in listening where that app or framework listens by default, or a one-line program in the `node` or `python` image that does the same with the standard library. Say which in `stubbed`.
- **The stand-in** is the lab's server, a static binary on an empty image, with no shell:
  - `image: ${WHYREACH_LAB_IMAGE:?set by the lab harness}` and `pull_policy: never`;
  - `command: ["serve", "0.0.0.0:3000"]` listens on each address given and accepts forever (`127.0.0.1:3000` for loopback only, `[::]:3000` for IPv6, several addresses for several ports); `--delay 5s` before the addresses waits before listening; `--close` closes each connection at once;
  - any other command exits with status 1, like a crashing app.
  A client that only needs to exist (it's where the failing connection starts) runs the stand-in listening on the app's own port.
- **Names.** Compose runs each file under a project named `whyreach-lab-<random>`, so service names, the default network and named networks need nothing. A `container_name:`, a network's `name:` or anything else Docker names globally must start with `whyreach-lab-` and should include `${REALCASE_PROJECT}` (the project's name, set by the harness) so runs don't collide. Keep the differences between names: a typo stays a typo.
- **Labels.** Give every service and network `labels: { io.whyreach.lab: "1" }`.
- **Ports.** A published host port the question fixes (`5432:5432`) is replaced by `${LAB_PORT}` (a free port the harness picks) on the host side, since a fixed port could be taken on this machine. The container side stays as the question has it.
- **Services on the host.** When the asker's server runs on the host, not in Docker, `host_listen` in `case.yaml` starts one for the run: `loopback` listens on 127.0.0.1, `docker0` on the default bridge's gateway. Its port is `${HOST_PORT}`, in `case.yaml` and as an environment variable for Compose.
- **Several Compose projects.** `compose.yaml` runs as the base project, `compose.<x>.yaml` as `<base>-<x>`.
- **Nothing on the host changes:** no firewall, route, DNS or sysctl changes, no files outside the case's folder.

## case.yaml

```yaml
source: https://stackoverflow.com/questions/12345
author: <the asker's display name>
licence: CC BY-SA 4.0          # Stack Overflow; omit for the forums and GitHub
asked: <what the asker reported, in a sentence or two of your own words>
projects: [compose.yaml]       # optional; default [compose.yaml]
up_wait: true                  # optional; false when a service is meant to crash or not become ready
settle_seconds: 15             # optional; how long to wait after `up` before checking (servers start)
host_listen: [loopback]        # optional
from: service:backend@${PROJECT}   # where the failing connection starts: service:<service>@${PROJECT}
                                   # (or @${PROJECT}-<x> for compose.<x>.yaml), or host
to: db:5432                    # what it connects to, as the asker's app wrote it (host:port)
symptom: refused               # what the asker saw: refused | timeout | name-not-found | no-route |
                               # reset-or-closed | failure (when the question doesn't say which)
images: [postgres:17-alpine]   # real images used, by tag
stubbed:
  - what: the backend, a Node.js app
    how: the stand-in, listening on 0.0.0.0:3000
    why: only its network setup matters to the failing connection
assumptions:
  - <each gap in the question you filled, and how>
read: [bin/realcases/raw/so-12345/question.md, test/realcases/README.md]
```

`${PROJECT}`, `${LAB_PORT}` and `${HOST_PORT}` are filled in by the harness in `from` and `to`. Before whyreach runs, the harness connects from `from` to `to` and checks that the failure matches `symptom`.
