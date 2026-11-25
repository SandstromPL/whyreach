<!-- Draft X (Twitter) thread for whyreach v0.2.0. Not posted: posting it is the owner's step. Numbers from docs/research/agent-benchmark/results.json (2026-11-21, the v0.2 run). Lengths counted as X counts them (a link is 23 characters): 275, 272 and 273 of 280. Plain words, as the owner asked. -->

# X thread: three posts

Post the first, then reply to it with the second, then reply to that with the third. X takes either one GIF or up to four images in a post, not both, so the demo and the chart go in different posts.

## Post 1, with the demo GIF

```
Ever had a Docker container that just can't reach another one, and no idea why?

I built whyreach for that. It tells you what's wrong and how to fix it, and it never changes anything. Use it yourself, or let your AI agent use it.

v0.2 just came out.

github.com/SandstromPL/whyreach
```

**Media:** `docs/assets/demo.gif` (1809×1227, 177 KB).

**Alt text:** Terminal recording. The demo's worker logs Connection refused for http://localhost:8080/. Then whyreach --from service:worker@whyreach-demo localhost:8080 names the cause, WR007: localhost inside worker is worker itself, not api. It lists the facts and the fix: connect to api:8080.

## Post 2, a reply: what's new

```
What's new in v0.2:

• Works on Windows too, through WSL2
• Spots 6 more problems: IPv6 localhost, internal networks, Docker subnets that clash with your VPN, silent drops, host firewalls, old container IPs
• Runs in GitHub Actions when tests fail

github.com/SandstromPL/whyreach/releases/tag/v0.2.0
```

**Media:** none.

## Post 3, a reply: the benchmark, with the chart

```
I tested it on 27 broken Docker setups: the same AI agent, once with just a shell, once with whyreach.

Both found the cause about as often. With whyreach: half the steps, under half the tokens, and 0 tries at docker exec or sudo (shell agent: 21).

github.com/SandstromPL/whyreach/blob/main/docs/research/agent-benchmark.md
```

**Media:** the chart as a PNG, rendered at 2× (1440×816) from `docs/assets/benchmark-dark.svg` (or `-light`) with headless Chrome. X doesn't take SVG.

**Alt text:** Bar chart of an AI agent with a shell against one with whyreach, on 27 Docker networking scenarios with Claude Haiku. Right causes: shell 21 of 27, whyreach 22 of 27. Tool calls, median: 6 against 3. Tokens, median: 49.7k against 20.2k. Time, median: 17.0 s against 6.6 s. Runs with an unsafe command: 21 of 27 against 0 of 27.

## Checked

- The six new problems are v0.2's six rules: WR014 (`localhost` that means `::1` too), WR015 (an `internal` network), WR013 (a Docker subnet that takes a VPN's or a LAN's range), WR016 (a silent drop), WR021 (the host's firewall) and WR024 (an address no container holds). "Runs in GitHub Actions when tests fail" is CI mode (`docs/ci.md`, `if: failure()`).
- "Both found the cause about as often": 21 of 27 for the shell agent, 22 for whyreach's.
- "half the steps, under half the tokens": medians of 3 tool calls against 6, and 20.2k tokens against 49.7k (41%).
- "0 tries at docker exec or sudo (shell agent: 21)": the shell agent's 21 refused attempts, one per run, were 19 `docker exec` (one behind `sudo`) and 2 `sudo`.
- The benchmark numbers are the summary of the v0.2 run (`docs/research/agent-benchmark.md`, "The v0.2 run").

# A standalone post: `localhost` in a container

A short post on its own, not part of the thread: the most common mistake, which the demo GIF shows. 247 of 280 characters.

```
localhost inside a Docker container isn't your machine. It's the container itself.

It trips up a lot of people. whyreach catches it, plus 19 other Docker network mistakes, and tells you the fix. It never changes anything.

github.com/SandstromPL/whyreach
```

**Media:** `docs/assets/demo.gif`, with the alt text of post 1. With media attached, X shows the GIF instead of a link card.

**Cards, if a post goes out without media:** a GitHub link shows the repository's card (its description, and its counts of contributors, issues, stars and forks); an MCPRush link shows that listing's card ("not scanned", 4 tools, v0.2.0), which doesn't say what whyreach does. Link GitHub, with the GIF or the chart attached.

# A post with the animation

For the 14.6-second animation (`whyreach-x-v02_x_1920x1080.mp4`, or the GIF `whyreach-x-v02_gif_1200x675.gif`; source in the Video Editor workspace, `projects/2026-11-25-whyreach-x-v02`). 220 of 280 characters.

```
Docker container can't reach another one? whyreach tells you why, and how to fix it. It never changes anything.

v0.2 is out: works on Windows too (WSL2), catches 6 more problems, and runs in CI.

github.com/SandstromPL/whyreach
```
