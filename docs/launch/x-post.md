<!-- Draft X (Twitter) thread for whyreach v0.2.0. Not posted: posting it is the owner's step. Numbers from docs/research/agent-benchmark/results.json (2026-11-21, the v0.2 run). Lengths counted as X counts them (a link is 23 characters): 255 and 273 of 280. Plain words, as the owner asked. -->

# X thread: two posts

X takes either one GIF or up to four images in a post, not both, so the demo and the chart go in two posts: the second as a reply to the first.

## Post 1, with the demo GIF

```
Ever had a Docker container that just can't reach another one, and no idea why?

I built whyreach for that. It tells you what's wrong and how to fix it, and it never changes anything.

Use it yourself, or let your AI agent use it.

github.com/SandstromPL/whyreach
```

**Media:** `docs/assets/demo.gif` (1809×1227, 177 KB).

**Alt text:** Terminal recording. The demo's worker logs Connection refused for http://localhost:8080/. Then whyreach --from service:worker@whyreach-demo localhost:8080 names the cause, WR007: localhost inside worker is worker itself, not api. It lists the facts and the fix: connect to api:8080.

## Post 2, a reply, with the benchmark chart

```
I tested it on 27 broken Docker setups: the same AI agent, once with just a shell, once with whyreach.

Both found the cause about as often. With whyreach: half the steps, under half the tokens, and 0 tries at docker exec or sudo (shell agent: 21).

github.com/SandstromPL/whyreach/blob/main/docs/research/agent-benchmark.md
```

**Media:** the chart as a PNG, rendered at 2× (1440×816) from `docs/assets/benchmark-dark.svg` (or `-light`) with headless Chrome. X doesn't take SVG.

**Alt text:** Bar chart of an AI agent with a shell against one with whyreach, on 27 Docker networking scenarios with Claude Haiku. Right causes: shell 21 of 27, whyreach 22 of 27. Tool calls, median: 6 against 3. Tokens, median: 49.7k against 20.2k. Time, median: 17.0 s against 6.6 s. Runs with an unsafe command: 21 of 27 against 0 of 27.

## Checked

- "Both found the cause about as often": 21 of 27 for the shell agent, 22 for whyreach's.
- "half the steps, under half the tokens": medians of 3 tool calls against 6, and 20.2k tokens against 49.7k (41%).
- "0 tries at docker exec or sudo (shell agent: 21)": the shell agent's 21 refused attempts, one per run, were 19 `docker exec` (one behind `sudo`) and 2 `sudo`.
- All from the summary of the v0.2 run (`docs/research/agent-benchmark.md`, "The v0.2 run").
