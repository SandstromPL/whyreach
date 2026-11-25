# Real cases: whyreach on setups people actually broke

> **What this is:** a check of whyreach against broken Docker setups taken from Stack Overflow, the Docker Community Forums and GitHub issues, each rebuilt here and diagnosed without knowing the answer. `INITIAL.md` §6.5.
> **Status:** method fixed on 2026-11-25, before any sampling, once the owner had settled the open decisions (see "Decisions"). Nothing has run yet.

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

Settled by the owner on 2026-11-25:
- no wrong cause at high confidence;
- right on at least 80% of covered cases with probe containers on.

Missing either doesn't stop a release. It says where the work goes next.

## Known limits

- Questions with an accepted answer lean towards problems that were simple to solve.
- Each case is rebuilt once, by an agent, from the question alone. A rebuild can miss what really broke the asker's setup; the symptom check catches only part of that.
- Linux with Docker Engine only; one Engine version (29.9.3).
- 20 cases measure orders of magnitude, not percentages to the point.

## What happened while sampling and labelling (2026-11-25)

Recorded as it happened, before whyreach ran on any case.

- **The pools.** Stack Overflow 649 questions, the forums 33 topics, GitHub 494 issues. GitHub's search counted 7,207 and 750 for the two queries but returned 494 distinct issues in all (it serves at most 1,000 per query, and fewer when its results are incomplete): the pool is what it returned.
- **Labelling ran in parallel.** To save time, seven labelers took the first 45 Stack Overflow, all 33 forum and the first 50 GitHub cases in chunks, in the shuffled order. The sample is still the first cases labelled `in`, in that order (`labels.py`); labels past the last case taken are counted in `labels.yaml`, not used. The second GitHub chunk (cases 26 to 50) was stopped once the first chunk had filled the quota.
- **Missing comments.** The Stack Exchange API returned the comments nested in each question without their text, so the first Stack Overflow labels were made without them. `fetch.py` now fetches comments per post; every Stack Overflow labeler re-read its threads with the comments and updated its labels. One label changed (so-65596446, from ambiguous to WR008), and several confirmations now rest on the asker's own comment.
- **Missing solution marks.** The forums mark the chosen post on the post, not the topic, so the forum threads first showed no solution. `fetch.py` was fixed; both forum labelers re-read their threads with the marks. No decision or rule changed.
- **GitHub isn't blind.** An issue is often opened after its reporter found the cause, so the issue's own text may state it, and the reproducer reads it. The rebuilds of the GitHub cases follow the issue as opened, without its comments, but can't be blind.
- **CLAUDE.md.** Every agent in this repository is given its CLAUDE.md, which describes whyreach's rules in a few words. The reproducers are told not to read the rule pages; they still had that summary.

## What happened while rebuilding (2026-11-25)

Also before whyreach ran on any case.

- **Five reproducers** rebuilt the 20 cases from the questions alone, in batches of four. None ran Docker. The symptom check then ran on each (`-realcases.symptoms-only`, no whyreach).
- **Operator changes,** each recorded in its case.yaml: so-78151189's Redis listens on `${LAB_PORT}` instead of 6379, on both sides, because this machine runs its own Redis on 127.0.0.1:6379; list items in four case.yaml files were quoted so they parse as text (content unchanged).
- **Label and rebuild must describe the same failing connection.** Comparing each rebuild's `from` and `to` with its label's connection (allowing for the harness's port substitutions, and a name the question doesn't give), three forum cases disagreed: the question showed one setup, and the confirmed fix was for a later one the asker moved to in the thread. Decided then, before any run: such a case is out as not rebuildable from the question, and the next eligible case takes its place (`real-cases/after-rebuild.yaml`). forum-130073, forum-150611 and forum-147588 went out; forum-139130 and forum-121911 came in. The forum pool then holds only 3 eligible cases, not 4.
- **One case can't be rebuilt as a running setup.** In gh-Anagamedina-ft_transcendence-309 the failure lives in the address nginx cached at its start, before the backend was recreated. Compose can't recreate a service after another starts, and the reproducer's workaround (writing that address into nginx's config and using it as the target) changes what the app named, against the rebuild rules. It stays in the sample as not reproduced, unscored.
- **One rebuild didn't fail:** gh-coryfinnegan-CollectionMaxxing-819 connected. Its reproducer got the one more try the method allows and changed nothing: the issue as opened reports a stale backup, not a failing connection (the startup race in its label comes from a maintainer's later comment). It stays in the sample as not reproduced, unscored.
- **forum-139130,** which came in for an excluded forum case, connected too: its question reports an HTTP 503 from a proxy that accepted the connection. After its one more try, not reproduced, unscored (its label was ambiguous as well).

## Before the run (2026-11-25)

The owner read the 19 labels and approved the run, and pulling `haproxytech/haproxy-alpine:2.4` for forum-127146, whose label depends on that image's own default configuration. Images used, by digest: `postgres:17` (`sha256:2838b352…`), `mysql:8.4` (`sha256:8c233bad…`), `redis:7-alpine` (`sha256:7aec734b…`), `nginx:stable-alpine` (`sha256:47928bf6…`), `node:22-alpine` (`sha256:1314fb30…`), `python:3.13-slim` (`sha256:8a7c3cd3…`) and `haproxytech/haproxy-alpine:2.4` (`sha256:6c1210f7…`).

## Decisions (2026-11-25, before sampling)

The owner settled the plan's four open decisions as proposed:
1. **Images:** the rebuilds may pull these official images from Docker Hub: Postgres, MySQL, Redis, nginx, Node.js and Python.
2. **Expectations:** as above.
3. **The split:** 12 Stack Overflow, 4 forum and 4 GitHub cases.
4. **The labels:** the owner reads them before the run.

Settled with them, before any case was looked at:
- **No package installs.** A rebuild runs the approved images as they ship: no `pip`, `npm` or `apt` at build or start. A framework that isn't in them (Flask, Express) becomes a stand-in that listens where that framework listens by default, and `case.yaml` says so. Any other server (MongoDB, RabbitMQ, Kafka) becomes the lab's stand-in, listening where its official image listens by default; when the case's cause depends on more of that server's own behaviour than its listen address, the owner is asked before its image is pulled.
- **Where things live.** The pools and the shuffled order: `docs/research/real-cases/pool-*.json`, from `docs/research/real-cases/sample.py`. What the labeler and the reproducer read (questions, answers, comments), fetched once: `bin/realcases/raw/`, outside git, since it's other people's text. The labels: `docs/research/real-cases/labels.yaml`, every case looked at, in order. The rebuilds: `test/realcases/<case>/`.
- **Blind by instruction.** The agents can read files, so the reproducer is told to read only its case's question and `test/realcases/README.md`; nothing enforces it. Each reproducer's report lists the files it read.
- **The symptom check** connects with the lab's server binary (`labserver check`, a 1-second connect) from a container that shares the source's network namespace, named `whyreach-lab-*` and labelled `io.whyreach.lab=1`, or from the harness itself when the source is the host.
