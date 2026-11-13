# ADR 0003: The MCP server: consent for probe containers, compact results, honest annotations

- **Status:** accepted (M2, 2026-11-13)
- **Answers:** `INITIAL.md` §10 Q3, and how §4.9–§4.10 are built
- **Builds on:** ADR 0001 (structured content is what Claude Code shows the model; tool names must be discoverable)

## Context

M2 puts whyreach behind an MCP server with four tools. Three questions had to be settled:

1. Tier 2b (probe containers) is off by default (§4.9), and "enable in config or approve through elicitation" left open *when* to ask, *how*, and with which clients (Q3).
2. The full `Diagnosis` JSON carries every evidence record. Agents need the answer, not the dump (§3.6: about 1.5k tokens).
3. `readOnlyHint` must be false when tier 2b is enabled (CLAUDE.md), but tier 2b can now change during a session.

## Decision 1: ask for probe containers only when they would help, once per session

- The server first runs the diagnosis (or probe) as configured. It asks only if the result has checks that tier 2b would run (`policy.NeedsProbeContainers`) and the cause isn't already settled at high confidence. A WR002 or WR008 diagnosis, which metadata and listeners settle, never asks.
- It asks **once per session**. A decline, a dismissal or a failed request is remembered, and the session carries on without probe containers. An approval turns tier 2b on for the rest of the session (the stdio process) and is never written to the config.
- **How it asks** depends on the protocol the client negotiated:
  - **before 2026-07-28:** a server-initiated `elicitation/create` with a one-field form (`allow`, a boolean, default true), awaited for up to two minutes;
  - **2026-07-28 and later,** where servers may no longer send that request (SEP-2322): an input request in the tool result, which the client answers by calling the tool again. The server keeps the request state it issued and accepts an answer only with that state, once. An answer the server didn't ask for (a forged `inputResponses`) changes nothing.
- Only clients that declare the `elicitation` capability are asked. The rest get the usual gap, which says how to enable probe containers in the config.
- The message says what the approval covers: probe containers for the rest of the session, from any container whyreach checks (it names the first); whyreach's own binary imported as a local image, with no registry pull, which stays because whyreach never deletes images; short-lived locked-down containers joined to the checked containers' network namespaces, then removed, along with labeled leftovers of earlier runs. (The first wording described one container in one namespace and "nothing else"; the M2 safety review found it understated the approval.)
- The advice in gaps and probe results ("approve them when whyreach asks, or set `probe_containers = true` in the config") is addressed to the user: turning a tier on is their decision. An agent that can write files must not edit the config to widen its own permissions; the text says so.
- **Why the user can trust it:** the question goes to the user through the client's own dialog. Tool arguments can't answer it, and no argument turns a tier on (`policy` has no such parameter). Every answer is in the audit log.

## Decision 2: a compact structured result, cut to a byte budget

- `report.Compact` derives the structured content from the full diagnosis: verdict, summary and ID first; findings, of which only the primary carries its explanation; short facts with evidence IDs; gaps; next checks; side effects; `changes_made`. No raw evidence: `save_report` writes it to a bundle.
- It must fit 6000 bytes of JSON. Past that it drops, in order: later facts, gap details, later findings, later gaps, the remaining facts, and finally the primary explanation. An `omitted` field says what went, and lists suppressed consequences. A test feeds it a diagnosis far over budget.
- The text content is the CLI's rendering of the same diagnosis, of similar size, for clients that ignore structured content. Both are golden-tested.

## Decision 3: annotations follow the permissions in effect

- `diagnose_connection` and `run_probe` are `readOnlyHint: true` while tier 2b is off, and `false` from the moment it is on: in the config at startup, or after an approval, when the server re-registers both tools (the SDK replaces them and notifies the client).
- `openWorldHint` is true exactly for those two (they send probes). `save_report` writes a file, so it is never read-only. `destructiveHint` is false and `idempotentHint` true for all four.

## Other decisions

- **Exactly four tools**, as §4.10 lists them. `inspect_environment` also accepts `service:<name>[@<project>]`, the same source grammar as `from`. `run_probe` returns every record its check produced (a lookup and its connects).
- **Errors are results:** a handler returns an error, and the SDK turns it into a result with `isError: true` that the model can read.
- **Logging** goes to stderr only. On connect the server logs the client's name, protocol and whether it declared elicitation, at info level (`WHYREACH_LOG=info`).
- **Wiring:** `main` wires the MCP server into the CLI's `mcp serve`; nothing else imports `mcpserver` or `cli`, and only `policy` builds an engine (`cmd/whyreach/imports_test.go`).

## Q3 answered

Which clients support elicitation for tier-2b consent? Claude Code 2.1.323, the dev box's, speaks protocol 2026-07-28 without an `initialize` handshake and declares elicitation, so it gets the input-request path. In headless mode (`claude -p`) it cancels the request at once: the diagnosis carries on without probe containers and the audit log records the answer, `cancel`. The table in `INITIAL.md` §10 Q3 has the details. The design doesn't depend on the answer: clients that declare the capability are asked, through whichever of the two protocol paths they use, and the others fall back to the config file, as Q3 required.

Because a 2026-07-28 client sends no `initialize`, the server logs who calls on the first tool call (client, protocol, elicitation), from the per-request metadata.

## Consequences

- A user who never wants probe containers can decline once per session, or leave the client without elicitation; the config file stays the durable switch.
- Headless runs (`claude -p`, CI) can't answer a dialog: they need `probe_containers = true` in the config if they want container-side DNS and TCP checks. The agent check (`make lab-agent`) does this.
- `readOnlyHint` can change during a session; a client that caches annotations from the first `tools/list` sees the change only if it honours `notifications/tools/list_changed`.
