#!/usr/bin/env bash
# M0 spike: does Claude Code pass our tool's text summary and structuredContent to the model?
# Runs ONE short headless session on a small model that may only call the spike tool.
# Nothing is added to your Claude Code config: the server is passed with
# --mcp-config + --strict-mcp-config for this run only.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p spikes/out
go build -o spikes/out/mcphello ./spikes/mcphello
go build -o spikes/out/serve ./spikes/probe

# A throwaway listener so the tool has something distinctive to report.
spikes/out/serve serve 127.0.0.1:18080 &
serve_pid=$!
trap 'kill "$serve_pid" 2>/dev/null || true' EXIT

cfg=$(printf '{"mcpServers":{"whyreach-spike":{"command":"%s"}}}' "$PWD/spikes/out/mcphello")
timeout 240 claude -p 'Call the host_listeners tool exactly once with {"port": 18080}. Then answer in two lines. Line 1: copy the exact text you received from the tool. Line 2: write "STRUCTURED: yes" if the tool result you received included a JSON object with a "listeners" field, otherwise "STRUCTURED: no".' \
  --model haiku --mcp-config "$cfg" --strict-mcp-config \
  --allowedTools mcp__whyreach-spike__host_listeners \
  --output-format stream-json --verbose > spikes/out/claude-stream.jsonl

python3 -I - spikes/out/claude-stream.jsonl <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    ev = json.loads(line)
    if ev.get("type") == "user":
        for block in ev.get("message", {}).get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_result":
                print("TOOL RESULT AS SEEN BY THE MODEL:", json.dumps(block.get("content"))[:1000])
    if ev.get("type") == "result":
        print("FINAL ANSWER:", ev.get("result"))
        print("turns:", ev.get("num_turns"), "| cost_usd:", ev.get("total_cost_usd"))
EOF
