# Launch drafts

Drafts for the launch, rewritten for v0.2.0 (2026-11-21) from the benchmark's v0.2 run (`docs/research/agent-benchmark.md`, "The v0.2 run"). The v0.1.0 drafts, from the benchmark's second run (2026-11-14), are in the git history; their results section became the README's. The launch post isn't posted yet, which is the owner's step.

- `launch-post.md`: the launch post. Its results tables are the v0.2 run's.
- `x-post.md`: a three-post X thread in plain words (the demo GIF, what's new in v0.2, then the benchmark chart), with alt texts.

Before publishing, check:
- the links: they assume the repository `SandstromPL/whyreach` is public and v0.2.0 is released (it is, since 2026-11-21);
- the numbers, against `docs/research/agent-benchmark/results.json` and `table.md`;
- that the claims stay within what v0.2 supports: Linux with Docker Engine, and Windows through WSL2 (Docker Engine in the distro, or Docker Desktop's WSL integration). Not Docker Desktop on macOS, nor native Windows or macOS builds.
