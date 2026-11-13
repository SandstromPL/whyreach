#!/usr/bin/env bash
# Pre-M1 spike: can the probe executor read a probe container's output through the
# Docker API (create → start → wait → logs → remove) when the container has AutoRemove?
#
# The M0 spikes used `docker run --rm`, which hides the question: the CLI attaches to
# the output streams before it starts the container. The product drives the API with
# the allowlist in INITIAL.md §4.8 (create, start, wait, logs, delete), which has no attach.
#
# Creates only whyreach-spike-lc-* containers (labeled io.whyreach.spike=1 and
# io.whyreach.probe=1) and removes them on exit.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=spikes/lib.sh
source spikes/lib.sh
mkdir -p "$OUT"
trap spike_cleanup EXIT
spike_cleanup
build_probe_image

SOCK=/var/run/docker.sock
API=v$(docker version --format '{{.Server.APIVersion}}')

# api METHOD PATH [JSON-BODY]: prints the HTTP status; the body goes to $OUT/api-body
api() {
  local args=(-sS --unix-socket "$SOCK" -X "$1" -o "$OUT/api-body" -w '%{http_code}')
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "http://docker/$API$2"
}

# create NAME AUTOREMOVE: a probe hardened as in INITIAL.md §3.3; prints the container ID
create() {
  local body
  body=$(printf '{"Image":"%s","Cmd":["report"],"User":"65534:65534","Labels":{"io.whyreach.spike":"1","io.whyreach.probe":"1"},"HostConfig":{"AutoRemove":%s,"NetworkMode":"none","CapDrop":["ALL"],"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges"],"PidsLimit":32,"Memory":33554432}}' "$SPIKE_IMG" "$2")
  api POST "/containers/create?name=$1" "$body" >/dev/null
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["Id"])' "$OUT/api-body"
}

# logs ID: prints "HTTP-status, N bytes" and the first line of an error body
logs() {
  local code
  code=$(api GET "/containers/$1/logs?stdout=1&stderr=1")
  printf '%s, %s bytes' "$code" "$(stat -c %s "$OUT/api-body")"
  [ "$code" = 200 ] || printf ' (%s)' "$(head -c 100 "$OUT/api-body")"
}

echo "== A. AutoRemove=true: create, start, wait, then read the logs (5 runs)"
for i in 1 2 3 4 5; do
  id=$(create "whyreach-spike-lc-a$i" true)
  api POST "/containers/$id/start" >/dev/null
  w=$(api POST "/containers/$id/wait?condition=not-running")
  echo "  run $i: wait → $w; logs → $(logs "$id")"
done

echo "== B. AutoRemove=false: create, start, wait, read the logs, then remove"
id=$(create whyreach-spike-lc-b false)
api POST "/containers/$id/start" >/dev/null
echo "  wait → $(api POST "/containers/$id/wait?condition=not-running") $(head -c 40 "$OUT/api-body")"
echo "  logs → $(logs "$id"); first frame header byte: $(head -c1 "$OUT/api-body" | od -An -tu1 | tr -d ' ') (1 = stdout)"
echo "  remove (force) → $(api DELETE "/containers/$id?force=1"); inspect afterwards → $(api GET "/containers/$id/json")"

echo "== C. AutoRemove=true, following the logs from before start"
id=$(create whyreach-spike-lc-c true)
curl -sS --unix-socket "$SOCK" -o "$OUT/lc-c-logs" \
  "http://docker/$API/containers/$id/logs?stdout=1&stderr=1&follow=1" &
follower=$!
sleep 0.3
api POST "/containers/$id/start" >/dev/null
wait "$follower"
echo "  followed logs: $(stat -c %s "$OUT/lc-c-logs") bytes"
