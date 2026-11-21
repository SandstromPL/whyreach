<!-- Draft X (Twitter) thread for whyreach v0.2.0. Not posted: posting it is the owner's step. Numbers from docs/research/agent-benchmark/results.json (2026-11-21, the v0.2 run). Lengths counted as X counts them (a link is 23 characters): 279 and 227 of 280. -->

# X thread: two posts

X takes either one GIF or up to four images in a post, not both, so the demo and the chart go in two posts: the second as a reply to the first.

## Post 1, with the demo GIF

```
Your container gets "Connection refused" and you don't know why.

whyreach tells you: the cause, the evidence and the fix. It only reads, never changes anything. A CLI and MCP server for your AI agent.

v0.2: Linux and Windows (WSL2), 20 causes, CI mode.

github.com/SandstromPL/whyreach
```

**Media:** `docs/assets/demo.gif` (1809×1227, 177 KB).

**Alt text:** Terminal recording. The demo's worker logs Connection refused for http://localhost:8080/. Then whyreach --from service:worker@whyreach-demo localhost:8080 names the cause, WR007: localhost inside worker is worker itself, not api. It lists the facts and the fix: connect to api:8080.

## Post 2, a reply, with the benchmark chart

```
27 broken Docker setups, Claude Haiku with a shell vs with whyreach:

• right cause: 21 vs 22
• tool calls: 6 vs 3
• tokens: 49.7k vs 20.2k
• tried docker exec or sudo: 21 runs vs 0

Method and raw data: github.com/SandstromPL/whyreach/blob/main/docs/research/agent-benchmark.md
```

**Media:** the chart as a PNG, rendered at 2× (1440×816) from `docs/assets/benchmark-dark.svg` (or `-light`) with headless Chrome. X doesn't take SVG.

**Alt text:** Bar chart of an AI agent with a shell against one with whyreach, on 27 Docker networking scenarios with Claude Haiku. Right causes: shell 21 of 27, whyreach 22 of 27. Tool calls, median: 6 against 3. Tokens, median: 49.7k against 20.2k. Time, median: 17.0 s against 6.6 s. Runs with an unsafe command: 21 of 27 against 0 of 27.

## Checked

- "tried docker exec or sudo: 21 runs vs 0": the shell agent's 21 refused attempts, one per run, were 19 `docker exec` (one behind `sudo`) and 2 `sudo`.
- The other numbers are the summary of the v0.2 run (`docs/research/agent-benchmark.md`, "The v0.2 run").
