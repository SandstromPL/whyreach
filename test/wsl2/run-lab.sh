#!/usr/bin/env bash
# The M6 manual lab run inside a WSL2 distro (docs/wsl2-lab.md): checks the
# setup, runs the unit tests, doctor and the lab, and writes a summary to
# send back. It changes nothing outside the repository and Docker resources
# named whyreach-lab-* or labeled io.whyreach.probe=1, as make lab does.
#
# Run it from the repository root:
#   test/wsl2/run-lab.sh                      the whole run
#   test/wsl2/run-lab.sh --summarize LAB_LOG  summarize a lab log again
#
# Every step writes to the summary and the script always reaches its end,
# failures included: the failing runs are the ones whose summary matters.
set -euo pipefail

cd "$(dirname "$0")/../.."

# scrub keeps this machine's names out of what you send back: your user and
# host names, your home directory, and your Windows user name in /mnt paths.
scrub() {
	local home=${HOME:-/nonexistent} user host args=()
	user=$(id -un 2>/dev/null || true)
	host=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || true)
	args+=(-e "s#${home}#~#g" -e 's#/mnt/([a-z])/Users/[^/ ]+#/mnt/\1/Users/<you>#g')
	# Names shorter than 3 characters would match ordinary words.
	[ "${#user}" -ge 3 ] && args+=(-e "s#\b${user}\b#<user>#g")
	[ "${#host}" -ge 3 ] && args+=(-e "s#\b${host}\b#<host>#g")
	sed -E "${args[@]}"
}

say() { printf '%s\n' "$*" | tee -a "$summary"; }

# summarize_lab writes the lab's results to the summary: the platform it
# found, each test's result, and the failing tests' own output. Every
# pipeline ends in "|| true": grep finds nothing in a lab that didn't
# start, and head stops reading a long failure.
summarize_lab() {
	local log=$1
	{ scrub <"$log" | grep -E '^lab: platform' || true; } | tee -a "$summary"
	{ scrub <"$log" | grep -E -- '^[[:space:]]*--- (PASS|FAIL|SKIP): Test' | sed -e 's/^[[:space:]]*//' || true; } | tee -a "$summary"
	local fails
	fails=$(grep -oE -- '--- FAIL: [^ ]+' "$log" | awk '{print $3}' | sort -u || true)
	if [ -n "$fails" ] || ! grep -qE '^ok[[:space:]]' "$log"; then
		say ""
		say "== failures, with whyreach's output (at most 400 lines)"
		# Scenarios run one after another, so each test's output runs from
		# its "=== RUN" line to the next one.
		{
			for name in $fails; do
				awk -v n="$name" '$0 == "=== RUN   " n {p = 1; print; next} /^=== (RUN|CONT|PAUSE|NAME)/ {p = 0} p' "$log"
			done | scrub | cut -c1-600 | head -n 400 || true
		} >>"$summary"
		{ grep -E '^(FAIL|ok|panic|#)|cannot|undefined|flag provided' "$log" | scrub | head -n 40 || true; } >>"$summary"
		{ echo "-- the lab log's last lines:"; tail -n 15 "$log" | scrub | cut -c1-600 || true; } >>"$summary"
		say "(the failing tests' output is in the summary file)"
	fi
}

if [ "${1:-}" = "--summarize" ]; then
	[ -f "${2:-}" ] || { echo "usage: $0 --summarize LAB_LOG" >&2; exit 2; }
	summary="$(dirname "$2")/summary-again.txt"
	: >"$summary"
	summarize_lab "$2"
	say ""
	say "Send back: $summary"
	exit 0
fi

out="bin/wsl2-lab/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
summary="$out/summary.txt"

finish() {
	local left
	left=$(docker ps -a --filter label=io.whyreach.probe=1 --format '{{.Names}}' 2>/dev/null | wc -l) || left=unknown
	say ""
	say "probe containers left: $left"
	say ""
	say "Send back: $summary"
}

fail() {
	say "STOPPED: $*"
	finish
	exit 1
}

say "whyreach WSL2 lab run, $(date -u +%Y-%m-%dT%H:%MZ)"
say "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown) ($(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown))"

# 1. The setup, without addresses or names.
case "$(uname -r)" in
*[Mm]icrosoft*) say "kernel: WSL2 ($(uname -r | sed -e 's/.*-microsoft/microsoft/'))" ;;
*) fail "this kernel isn't WSL2's ($(uname -r)): run this inside a WSL2 distro" ;;
esac
interop=none
for f in /proc/sys/fs/binfmt_misc/WSLInterop /proc/sys/fs/binfmt_misc/WSLInterop-late; do
	[ -e "$f" ] && interop=$(basename "$f")
done
say "WSL interop entry: $interop"
[ "$interop" != none ] || say "  (interop is off in /etc/wsl.conf, so whyreach will classify this distro as plain Linux)"
# WSL's version and networking mode (NAT or mirrored) change what localhost
# and host.docker.internal reach; neither prints an address.
if command -v wslinfo >/dev/null; then
	say "WSL: version $(wslinfo --wsl-version 2>/dev/null || echo unknown), networking $(wslinfo --networking-mode 2>/dev/null || echo unknown)"
else
	say "WSL: wslinfo isn't here (an older WSL), version and networking mode unknown"
fi
say "init: $(cat /proc/1/comm 2>/dev/null || echo unknown)"
command -v go >/dev/null || fail "go isn't on PATH (docs/wsl2-lab.md, step 2)"
command -v make >/dev/null || fail "make isn't installed (docs/wsl2-lab.md, step 2)"
command -v docker >/dev/null || fail "docker isn't on PATH: Docker Engine in this distro, or Docker Desktop's WSL integration for it (docs/wsl2-lab.md, step 1)"
say "go: $(go version 2>&1 | cut -d' ' -f3-)"
if ! server=$(docker version --format '{{.Server.Platform.Name}} {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}}, API {{.Server.APIVersion}})' 2>&1); then
	say "docker: $(printf '%s' "$server" | scrub | tail -n 3 || true)"
	fail "Docker doesn't answer: start dockerd (sudo systemctl start docker) or Docker Desktop"
fi
say "docker: $server"
say "compose: $(docker compose version --short 2>&1 || echo missing)"

# 2. Build and unit tests (these include the stdin-EOF test of mcp serve).
say ""
say "== make build test"
if make build test >"$out/unit.log" 2>&1; then
	say "unit tests: PASS"
else
	say "unit tests: FAIL (from $out/unit.log):"
	{ scrub <"$out/unit.log" | grep -E -- '--- FAIL|FAIL|panic|error' | head -n 30 || true; } | tee -a "$summary"
	{ echo "-- its last lines:"; tail -n 10 "$out/unit.log" | scrub | cut -c1-400 || true; } | tee -a "$summary"
fi

# 3. doctor: which setup whyreach found.
say ""
say "== whyreach doctor"
if [ -x ./bin/whyreach ]; then
	./bin/whyreach doctor >"$out/doctor.txt" 2>&1 || true
	{ scrub <"$out/doctor.txt" | grep -E '^[^ ]+ (docker|platform|wsl idle shutdown|container listeners|netns executor|probe containers|mcp) ' | cut -c1-400 || true; } | tee -a "$summary"
else
	say "no bin/whyreach: the build failed (step 2)"
fi

# 4. The lab. It prints the platform it found first.
say ""
say "== make lab (about a minute; log in $out/lab.log)"
start=$(date +%s)
lab=0
go test -tags lab -count=1 -v ./test/e2e/... >"$out/lab.log" 2>&1 || lab=$?
say "lab: exit $lab after $(($(date +%s) - start)) s"
summarize_lab "$out/lab.log"

# 5. What's left behind: nothing of the lab's.
finish
