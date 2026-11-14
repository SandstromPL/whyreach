<!-- Draft: a section for the top-level README, to paste after "Try it: the demo" once v0.1.0 is released. Not published. -->

## How it compares to a shell

An agent can already debug Docker networking with a shell: `docker inspect`, `ss`, `curl`. To see what whyreach adds, two headless Claude Code agents on Claude Haiku got the same problem report for each of the 21 lab scenarios (`test/lab`). One had only a shell, held to read-only access to the lab. The other had only whyreach's four MCP tools, in whyreach's default configuration.

| | Shell agent | whyreach agent |
|---|---|---|
| Named the right cause | 20 of 21 | 20 of 21 |
| Tool calls, median | 6 | 2 |
| Tokens, median | 38.9k | 12.5k |
| Time, median | 16.6 s | 6.5 s |
| Cost, all 21 runs | $0.060 | $0.023 |
| Commands that would change something, attempted | 18, in 18 runs | 0 |

Each agent found 20 of the 21 causes, and each missed a different one. whyreach's agent got there with about a third of the tokens and less than half the time. It never reached for `docker exec`; the shell agent did in 18 of its 21 runs, to look inside containers, and the benchmark's guard refused each one.

The method was fixed before the first run. That run's agents could see each scenario's name in their directory names, so it was run again with only that changed; these are the second run's numbers. The per-scenario results, the raw data and the caveats are in [docs/research/agent-benchmark.md](docs/research/agent-benchmark.md): one model, one run each, and stand-in servers that are easier to read than real applications. To run it yourself, use `make lab-bench`; it needs Docker, `bwrap` and the `claude` CLI.
