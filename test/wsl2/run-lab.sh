#!/usr/bin/env bash
# The M6 manual lab run inside a WSL2 distro (docs/wsl2-lab.md): checks the
# setup, runs the unit tests, doctor and the lab, and writes a summary to
# send back. It changes nothing outside the repository and Docker resources
# named whyreach-lab-* or labeled io.whyreach.probe=1, as make lab does.
#
# Run it from the repository root:  test/wsl2/run-lab.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
out="bin/wsl2-lab/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
summary="$out/summary.txt"

# scrub keeps this machine's names out of what you send back: your user and
# host names and your home directory.
scrub() {
	local home=${HOME:-/nonexistent} user host
	user=$(id -un)
	host=$(hostname)
	sed -e "s#${home}#~#g" -e "s#\b${user}\b#<user>#g" -e "s#\b${host}\b#<host>#g"
}

say() { printf '%s\n' "$*" | tee -a "$summary"; }
fail() {
	say "STOPPED: $*"
	say "Send back: $summary"
	exit 1
}

say "whyreach WSL2 lab run, $(date -u +%Y-%m-%dT%H:%MZ)"
say "commit: $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))"

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
command -v go >/dev/null || fail "go isn't on PATH (docs/wsl2-lab.md, step 2)"
command -v make >/dev/null || fail "make isn't installed (docs/wsl2-lab.md, step 2)"
command -v docker >/dev/null || fail "docker isn't on PATH: Docker Engine in this distro, or Docker Desktop's WSL integration for it (docs/wsl2-lab.md, step 1)"
say "go: $(go version | cut -d' ' -f3-)"
if ! server=$(docker version --format '{{.Server.Platform.Name}} {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}}, API {{.Server.APIVersion}})' 2>&1); then
	say "docker: $(printf '%s' "$server" | scrub | tail -n 3)"
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
	say "unit tests: FAIL (tail of $out/unit.log):"
	scrub <"$out/unit.log" | grep -E -- '--- FAIL|FAIL|panic|error' | head -n 30 | tee -a "$summary"
fi

# 3. doctor: which setup whyreach found.
say ""
say "== whyreach doctor"
./bin/whyreach doctor >"$out/doctor.txt" 2>&1 || true
scrub <"$out/doctor.txt" | grep -E '^[^ ]+ (docker|platform|wsl idle shutdown|container listeners|netns executor|probe containers|mcp) ' | cut -c1-400 | tee -a "$summary"

# 4. The lab. It prints the platform it found first.
say ""
say "== make lab (about a minute; log in $out/lab.log)"
start=$(date +%s)
set +e
go test -tags lab -count=1 -v ./test/e2e/... >"$out/lab.log" 2>&1
lab=$?
set -e
say "lab: exit $lab after $(($(date +%s) - start)) s"
scrub <"$out/lab.log" | grep -E '^lab: platform' | tee -a "$summary"
scrub <"$out/lab.log" | grep -E -- '^[[:space:]]*--- (PASS|FAIL|SKIP): Test' | sed -e 's/^[[:space:]]*//' | tee -a "$summary"
if [ "$lab" -ne 0 ]; then
	say ""
	say "== failures, with whyreach's output"
	# Scenarios run one after another, so each test's output runs from its
	# "=== RUN" line to the next one.
	for name in $(grep -oE -- '--- FAIL: [^ ]+' "$out/lab.log" | awk '{print $3}' | sort -u); do
		awk -v n="$name" '$0 == "=== RUN   " n {p = 1; print; next} /^=== (RUN|CONT|PAUSE|NAME)/ {p = 0} p' "$out/lab.log"
	done | scrub | cut -c1-600 | head -n 400 >>"$summary"
	grep -E '^(FAIL|ok|panic)' "$out/lab.log" | scrub >>"$summary" || true
	say "(the failing tests' output is in the summary file)"
fi

# 5. What's left behind: nothing of the lab's.
left=$(docker ps -a --filter label=io.whyreach.probe=1 --format '{{.Names}}' | wc -l)
say ""
say "probe containers left: $left"
say ""
say "Send back: $summary"
