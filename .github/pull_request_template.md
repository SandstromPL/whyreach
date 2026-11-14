## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## How I checked it

- [ ] `make build test lint`
- [ ] `make lab` (needed when behaviour changes; CI doesn't run it)
- [ ] `make lab-root` or `make lab-agent`, if relevant

## Checklist

- [ ] The change keeps the safety rules in [CONTRIBUTING.md](https://github.com/SandstromPL/whyreach/blob/main/CONTRIBUTING.md#the-safety-rules): read-only, no shell, bounded probes, no secrets.
- [ ] If the design changed, INITIAL.md or an ADR says so.
- [ ] A new rule comes with fixtures, a lab scenario, a `docs/rules` page and a catalog entry.
- [ ] Tests and fixtures use made-up values only.
