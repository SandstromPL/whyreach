# M0 spikes (throwaway code)

This directory exists to answer the M0 open questions in `INITIAL.md` §10. The results are recorded in `docs/adr/0001-execution-contexts.md`. **Nothing here is product code.** M1 may promote small pieces (for example the `/proc/net` parser) into `internal/`.

| Spike | How to run | Answers |
|---|---|---|
| Probe container: shared netns, resolver files, listeners, hardening, timing | `spikes/probecontainer.sh` | §10 Q2, Q4 |
| What a `docker`-group user can see without root | `spikes/privileges.sh` | §10 Q1 |
| MCP hello tool (official Go SDK, structured output) | `go test ./spikes/mcphello/` and `spikes/mcphello/claude-check.sh` | MCP SDK fit |

The Docker resources the scripts create:
- **Names:** `netdoctor-spike-*`
- **Labels:** `io.netdoctor.spike=1`, plus `io.netdoctor.probe=1` on probe containers

The scripts remove these resources when they exit and sweep leftovers when they start. Nothing else on the machine is touched, and no image is pulled from a registry: the probe image is built locally from `spikes/probe` with `docker import`.

Raw outputs go to `spikes/out/`, which git ignores.
