# Security policy

## Supported versions

Security fixes go into the latest release, currently 0.1.x.

## Reporting a vulnerability

Please don't open a public issue. Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to [the private report form](https://github.com/SandstromPL/whyreach/security/advisories/new).

Include:

- what you found and what an attacker could do with it;
- the steps or setup to reproduce it;
- the whyreach version (`whyreach --version`), and how you ran it: the CLI, an MCP client, the container image, or as root.

whyreach is maintained by one person, so allow a few days for a reply. Once a fix is released, the advisory is published with credit to you, unless you'd rather stay anonymous.

## What counts

whyreach is built to be safe to point at a machine you care about, and to hand to an AI agent. These are in scope:

- **Changes it promises not to make:** containers, networks, routes, firewall rules, DNS, or files outside whyreach's own directories. The only Docker writes allowed are the optional probe image and probe container, and only after the user allows them.
- **Getting around the probe limits:** more than one host:port per call; ranges, lists or wildcards; link-local or cloud-metadata addresses; or a probe that sends data.
- **Widening permissions:** an MCP tool argument that widens what whyreach may do, or a way past the user's approval for outside names and private addresses.
- **Leaking secrets:** environment variable values, file contents other than `resolv.conf` and `hosts`, or Docker credentials reaching evidence, reports or an agent.
- **Hostile container text:** names, labels or error messages that inject instructions into an agent, or escape sequences that reach a terminal.
- **The root executor:** entering the wrong network namespace, or reading outside a container's root.
- **Redaction:** a redacted report export that still shows what redaction should hide.

## How whyreach stays safe

- **The read-only promise comes from whyreach's code, not from OS permissions.** whyreach needs the Docker socket, which is as powerful as root. Its code limits the Docker client to an allowlist of endpoints, runs no shell, and checks every probe against the policy when it dials. If you want the OS to enforce read-only access as well, put a read-only Docker socket proxy in front of it.
- **Through MCP, permissions never come from the agent.** They come only from your config, or from your answer to a question in your MCP client. An agent's arguments can only narrow them.
