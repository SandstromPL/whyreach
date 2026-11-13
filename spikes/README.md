# M0 spikes (throwaway code)

This directory exists to answer the M0 open questions in `INITIAL.md` §10. The results are recorded in `docs/adr/0001-execution-contexts.md`. **Nothing here is product code.** M1 promoted three pieces: the `/proc/net` parser (now in `internal/probe`), the probe's `serve` and `check` modes (now the lab's stand-in server, `test/labserver`), and the E1/E2/E4 scenarios (now `test/lab/`).

| Spike | How to run | Answers |
|---|---|---|
| Probe container: shared netns, resolver files, listeners, hardening, timing | `spikes/probecontainer.sh` | §10 Q2, Q4 |
| What a `docker`-group user can see without root | `spikes/privileges.sh` | §10 Q1 |
| MCP hello tool (official Go SDK, structured output) | `go test ./spikes/mcphello/` and `spikes/mcphello/claude-check.sh` | MCP SDK fit |
| Rule experiments: reproduce the top real-world failures and record what whyreach can observe | `spikes/experiments.sh` (scenarios in `spikes/experiments/`) | `docs/research/rule-experiments.md`, ADR 0002 |
| Probe lifecycle through the Docker API: can whyreach read a probe's output when it uses AutoRemove? | `spikes/probelifecycle.sh` | ADR 0001 amendment |

The Docker resources the scripts create:
- **Names:** `whyreach-spike-*`, plus `whyreach-exp-*` for the experiments' Compose projects and containers
- **Labels:** `io.whyreach.spike=1`, plus `io.whyreach.probe=1` on probe containers

The scripts remove these resources when they exit and sweep leftovers when they start. Nothing else on the machine is touched, and no image is pulled from a registry: the probe image is built locally from `spikes/probe` with `docker import`.

Raw outputs go to `spikes/out/`, which git ignores.
