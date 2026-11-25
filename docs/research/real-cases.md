# Real cases: whyreach on setups people actually broke

> **What this is:** a check of whyreach against broken Docker setups taken from Stack Overflow, the Docker Community Forums and GitHub issues, each rebuilt here and diagnosed without knowing the answer. `INITIAL.md` §6.5.
> **Status:** planned on 2026-11-25. The method below is a draft: it is fixed, and committed, only once the owner has settled the open decisions at the end. Nothing has run.

## Why

Every test so far runs on setups whyreach's author built from whyreach's own rule list: the 356 fixtures, the 28 lab scenarios, `make lab-agent` and the agent benchmark. The research behind the rule list (`failure-signatures.md`, 2026-11-13) ranked real problems, but no real setup was ever rebuilt and diagnosed. The lab's servers are stand-ins whose listen addresses are set by hand, while a real server's own defaults (Flask's dev server, Redis, MySQL's `bind-address`) are often the cause.

This check answers three questions:
1. **Coverage:** of the connection problems people bring, what share falls within whyreach's rules and supported platforms?
2. **Accuracy:** where a rule covers the cause, how often does whyreach name it?
3. **Trust:** how often does whyreach name a wrong cause? This is the worst outcome. "Inconclusive" is an honest answer; a wrong cause sends the user the wrong way.

## Sources and sampling

20 cases, from three sources, each sampled at random from a pool fetched by fixed queries:

| Source | Cases | Pool | Queries |
|---|---|---|---|
| Stack Overflow | 12 | Stack Exchange API `/search/advanced`, questions with an accepted answer, created from 2021-01-01 | tagged `docker-compose` with `connect`, `refused`, `resolve` or `reach` in the title; tagged `docker` with `connection refused` in the title; tagged `docker-compose` with `services` and `ECONNREFUSED` in the body |
| Docker Community Forums | 4 | `/search.json`, topics marked solved, from 2021-01-01 | `connection refused`, `could not resolve`, `can't connect`, `timed out` |
| GitHub issues | 4 | `gh api search/issues`, closed issues from 2023-01-01, any repository | `"docker compose" "connection refused"`, `"docker-compose.yml" "ECONNREFUSED"` |

Pool sizes measured on 2026-11-25, before any sampling (overlaps between queries not removed): Stack Overflow 371 (`connect`), 82 (`refused`), 34 (`resolve`), 18 (`reach`), 174 (`docker`, `connection refused`) and 60 (`ECONNREFUSED`); the forums' first query 15; GitHub 7,207 and 750.

**Sampling:** for each source, the union of its queries' results, without duplicates, sorted by ID, then shuffled with the seed `20261125` (Python's `random.Random(seed).shuffle`). Cases are taken in that order, and each is checked for eligibility until the source's quota is filled. Every case looked at is listed in the results with its outcome, so the exclusions show what whyreach can't serve.

Why from 2021: Compose v2 and today's Docker Engine. Older answers often rest on `links`, legacy Compose file versions or long-fixed Docker bugs.

## Eligibility

Decided from the question and its confirmed fix, before anything is rebuilt.

**In** when all of these hold:
- something fails to connect to something else: container to container, container to host, host to container, or container to the outside;
- the question gives enough of the setup to rebuild it (a Compose file, or the `docker run` commands);
- the fix is confirmed: an accepted answer, the asker's own answer, or a closing comment from the reporter or a maintainer saying what fixed it;
- the cause reproduces on Linux with Docker Engine without changing this machine's routes, firewall, sysctl, DNS or VPN. An asker on a Mac is in when the cause is the same on Linux (`localhost` inside a container is).

**Out**, with the reason recorded:
- **platform:** the cause exists only on Docker Desktop for macOS or Windows outside WSL2, Kubernetes, Swarm, Podman or rootless Docker. Counted apart: it is the share v0.3 (M7) is for;
- **host change:** reproducing it needs a change to this machine's network setup;
- **not a connection failure:** a crash, a failed login over a working connection, TLS, an HTTP status, or a Docker bug fixed in a later release;
- **not rebuildable**, or **no confirmed fix**.

## Keeping it blind

Three steps, each by a fresh agent that sees only what is listed. No agent in these steps sees whyreach's code or output.

1. **The labeler** gets the question, its answers and comments, and the rule catalog (`docs/rules/*.md` and the table in `INITIAL.md` §4.6). It writes: in or out, and why; the cause in plain words; the rule that covers it, or `outside` when none does, or `ambiguous`; and the confirmed fix.
2. **The reproducer** gets the question only: no answers, no comments, no label. It rebuilds the setup as `test/realcases/<id>/compose.yaml` and `case.yaml` (the source, the target as the asker's app used it, the images, and what it stubbed and why).
3. **The symptom check** (the harness, no whyreach): from the source, a plain connect or lookup to the target, as the asker's app made it. The rebuild counts only when the failure matches the question's: refused, timeout, name not found or no route. On a mismatch the reproducer gets one more try, told only the mismatch; after that the case is "not reproduced".

The owner reads the labels. The case list, the labels and the rebuilds are committed before whyreach runs on any case.

## Rebuilding

- **Real servers:** a case uses the real image (Postgres, MySQL, Redis, nginx, Node.js, Python) pinned by digest when the server's own behaviour can matter, and a real framework's default rather than a hand-set listen address. The client side may be the lab's stand-in when only its network setup matters.
- **Names:** every Compose project is `whyreach-lab-<random>`, and `container_name`, network `name:` and external networks get a `whyreach-lab-` prefix. Differences between names are kept (a typo stays a typo), so the rebuild touches only Docker resources the lab may touch.
- **Services on the host** (`host.docker.internal` cases) are the harness's own listener, as in the lab.
- **Attribution:** each `case.yaml` links its source and names its author. Snippets from Stack Overflow are under CC BY-SA 4.0, noted in `test/realcases/README.md`.

## The run

`make lab-realcases` (to build): a Go test (tags `lab,realcases`) brings up each case, runs the symptom check, then runs `whyreach diagnose --json --from <source> <target>` twice, with the default config and with probe containers on. It records the verdict, the primary rule and its confidence, what else was found, and the fix. No agent and no model: this is whyreach's own answer. An agent arm can come later; the benchmark is on hold.

## Scoring

Fixed before the run, for each case and config:
- **Right:** the primary finding is the labelled rule.
- **Partly right:** the labelled rule is only among the other findings.
- **Inconclusive:** no cause named. The right answer for an `outside` case; a miss for a covered one.
- **Wrong:** a cause other than the label (for an `outside` case, any cause). Wrong at high confidence is reported apart.
- **The fix:** does whyreach's fix do what the confirmed fix did? Yes, partly or no, judged by a fresh agent that gets both texts without the rule IDs, and checked by the owner.

`ambiguous` labels are reported, not scored.

## What gets reported

- The funnel: cases looked at, in, rebuilt and run, with every exclusion and its reason, the platform ones apart.
- Coverage: covered cases out of those rebuilt.
- Accuracy on covered cases, under each config.
- Every wrong cause, with its confidence and why it happened.
- A table of all cases.

The results are reported as they come out of the first run. Bugs it finds are fixed afterwards through the rule checklist (a fixture and a lab scenario each), and a re-run after the fixes is reported next to the first, never in its place.

## Expected, before the run

Proposed, for the owner to settle:
- no wrong cause at high confidence;
- right on at least 80% of covered cases with probe containers on.

Missing either doesn't stop a release. It says where the work goes next.

## Known limits

- Questions with an accepted answer lean towards problems that were simple to solve.
- Each case is rebuilt once, by an agent, from the question alone. A rebuild can miss what really broke the asker's setup; the symptom check catches only part of that.
- Linux with Docker Engine only; one Engine version (29.9.3).
- 20 cases measure orders of magnitude, not percentages to the point.

## Open decisions for the owner

1. **Images:** the rebuilds pull official images from Docker Hub (Postgres, MySQL, Redis, nginx, Node.js and Python), about 1 to 2 GB. Pull them?
2. **The expectations** above.
3. **The split** of 12 Stack Overflow, 4 forum and 4 GitHub cases.
4. **Reading the labels** before the run: the plan has the owner do it.
