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

## Amendment (2026-11-13, before M4): outside names need approval; `save_report` always redacts

The owner settled `INITIAL.md` §10 Q11 and Q12. M4 builds both.

- **Outside names (Q11).** A DNS query delivers its name to whoever serves the domain. An agent whose own network is blocked could therefore leak data through this server, by asking it to look up names like `<data>.attacker.example`.
  - Through MCP, a name with a dot that Docker doesn't resolve itself is now looked up only in two cases: the user approves that exact name through the same elicitation paths as Decision 1, or the name falls under a domain listed in `[probe] names`.
  - Unlike probe containers, approval is per name, not per session. One yes must not open the channel for the rest of the session.
  - Without an answer, nothing is sent, and the gap names the setting.
  - Refusing such names outright was rejected, because WR020 diagnoses exactly those lookups.
  - Names without a dot stay free: their queries reach only the resolver and the user's own search domains.
- **`save_report` (Q12).** The `redact` argument goes. Bundles saved through MCP are always redacted, and unredacted ones come only from the CLI, so no tool argument relaxes a privacy default.
- **Headless runs.** As with probe containers, `claude -p` and CI can't answer a dialog. They need `[probe] names` for the outside names they diagnose, and the agent check needs it for WR020's scenario.

## Amendment (M4, 2026-11-13): outside names and save_report, as built

- **Where the rule holds.** The probe enforces it at the moment of sending, for every executor: in-process, in a probe container (`__probe --names`), and through the netns executor. The hosts file answers first, as it does for the app. A lookup that the hosts file doesn't answer and whose name the limits hold back sends nothing. Its record is a skipped check with code `policy_denied` and the fixed message `probe.NameNotApproved`, and a connect to the name shares that reason, so the two make one gap that names `[probe] names`. Enforcing it in the policy alone was rejected: only the probe sees the source's hosts file, and the address allowlist already holds at dial time in the same way.
- **Outside names** are names with a dot, other than `localhost`, `*.localhost` and Docker's fixed names `host.docker.internal` and `gateway.docker.internal`. `*.localhost` goes with `localhost`, since RFC 6761 keeps those names local. An address is not a name.
- **Which names go through.** For MCP clients only, the policy lists the outside names a batch may look up: names Docker's metadata knows, names `[probe] names` covers, and names the user approved this session. For a diagnosis, the engine answers "does Docker know this name?" from the containers it already observed. For `run_probe`, it reads the container list, then inspects up to 64 containers on the source's networks for aliases, and only when the policy needs the answer. A name qualified with a network (`api.shop_default`), which Docker's DNS answers too, counts as known. Any metadata name counts, even one the source can't resolve itself: such names carry nothing an agent chose. `[probe] names` entries need at least two labels, so a top-level domain can't turn the rule off.
- **Asking.** Only an unsettled diagnosis or a `run_probe` with a held-back name asks. The server asks once per name per session, at most three times a session, through the same two paths as Decision 1, and runs the check again on approval. The question doesn't pre-approve (`allow` defaults to false) and says to allow only an expected name: an agent can pick any name, and a stream of dialogs invites a careless yes. Past three, a held-back name is only a gap. When probe containers are needed too, they are asked about first. On the 2026-07-28 path, the request state records the question it carries (probe containers, or which name), and an answer counts only for that question: an approval sent under another key approves nothing, and the unanswered question counts as declined. An approval covers the exact name and not its subdomains. Each answer is an audit entry of its own (`name_lookup_consent`), and a held-back lookup counts as denied, not sent.
- **Nameservers.** A nameserver from the source's `resolv.conf` on the block list gets no query, from any client. Like the C libraries, a lookup uses the first three. When the first is blocked, the app's own lookup would go there, so whyreach makes none: a lookup through the others would describe one the app doesn't make, and could read as "doesn't resolve" or "times out". When a later one is blocked, the lookup uses only those before it, asked in glibc's order; when neither of its queries (A, AAAA) gets a reply glibc accepts (only no answer, SERVFAIL, REFUSED or NOTIMP), the app would ask the blocked one next, so the lookup is refused rather than reported as failing. One accepted reply ends glibc's lookup there, answered or not. musl asks every nameserver at once, so a musl app may take an answer from a blocked one; the record's limitations say so. Addresses are read as glibc and musl read them (`0xa9fea9fe` is 169.254.169.254). The nameservers are checked before the name, so the user isn't asked about a name that can't be looked up anyway. A lookup refused before any query counts as denied in the audit; one refused after its queries went out counts as sent.
- **Residual risks, accepted with the decision** (raised by the reviews; the owner may revisit them, `INITIAL.md` §10 Q13–Q15):
  - A container that rewrites its own `resolv.conf` decides where its free names go: its search domains expand names without a dot, and its nameservers receive every lookup, approved ones included. It already sees the agent's TCP probes to it, so this isn't a new kind of channel.
  - Names without a dot are harmless only where the resolver and the search domains are the user's own. On an untrusted network (a hostile Wi-Fi's DHCP-supplied resolver and search domain), or where systemd-resolved multicasts single-label names (LLMNR), they reach other hands.
  - An approval holds for the session, as decided, so the approved name can be looked up again and again. Whoever serves that domain sees each query, and their timing can carry a few bits a minute within the rate limit.
- **`save_report`** takes only `diagnosis_id`. The input schema rejects any other argument, so a call that passes `redact` fails and is audited as refused. A golden file pins the four tools' schemas and annotations (`internal/mcpserver/testdata/tools.golden`).

## Amendment (2026-11-14, before v0.1.0): approvals get a budget; private addresses ask too

The owner settled `INITIAL.md` §10 Q13–Q15 after the experiments in `docs/research/q13-q15-experiments.md`. All three are to be built before v0.1.0 is tagged.

- **A budget per approval (Q14).**
  - E2 showed that every repeated lookup reaches the domain's server. A cache wouldn't change that, since the domain's owner sets the TTL. An approval held for the session was therefore a timing channel running at the full rate limit.
  - An approval now covers 3 lookups of the name. A fourth asks again, within the session's limit of 3 questions.
  - No agent scenario needed more than 3.
- **Private addresses (Q15).**
  - The address, port and timing of a TCP probe can carry data to a host on a routed private network.
  - Through MCP, probes to loopback, Docker's networks and the host's own addresses stay free.
  - Any other address the `rfc1918` class admits needs the user's approval for that exact address and port, asked and budgeted like names. An explicit CIDR or address in `[probe] allow` covers it without asking.
  - Narrowing the default to Docker's networks was rejected. Connections through the host's LAN address, and to LAN and VPC services, would become uncheckable (E3).
- **Cloud resolvers (Q13)** are a probe-policy matter, not an MCP one. The host's own resolver may be asked even at a blocked address, for DNS only. A blocked address that only a container names stays refused.
