#!/usr/bin/env bash
# M0 spike: does a probe container started with --network container:X see X's world?
# Answers INITIAL.md §10 Q2 and Q4. Creates only netdoctor-spike-* resources and removes them on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=spikes/lib.sh
source spikes/lib.sh
mkdir -p "$OUT"
trap spike_cleanup EXIT
spike_cleanup

echo "== 1. import a static probe binary as a FROM-scratch image"
build_probe_image
echo "probe binary: $PROBE_BYTES bytes; docker import: ${IMPORT_MS} ms"

echo "== 2. start two distroless services on a user-defined network"
start_services
docker ps --filter "label=$SPIKE_LABEL" --format '{{.Names}}: {{.Status}}'

# Hardened like the product's probe (INITIAL.md §3.3).
PROBE=(--rm --label "$PROBE_LABEL" --cap-drop ALL --user 65534:65534 --read-only
       --security-opt no-new-privileges --pids-limit 32 --memory 32m)

echo "== 3. hardened probe inside api's netns (3 timed runs)"
for i in 1 2 3; do
  t0=$(now_ms)
  docker run "${PROBE[@]}" --network container:netdoctor-spike-api "$SPIKE_IMG" report \
    --dns api --dns netdoctor-spike-worker --dns spike-extra --dns does-not-exist.invalid \
    --tcp 127.0.0.1:8080 --tcp 127.0.0.1:9090 > "$OUT/probe-in-api.json"
  echo "run $i: $(( $(now_ms) - t0 )) ms"
done
cat "$OUT/probe-in-api.json"

echo "== 4. hardened probe inside worker's netns: can worker reach api?"
docker run "${PROBE[@]}" --network container:netdoctor-spike-worker "$SPIKE_IMG" report \
  --dns api --tcp api:8080 --tcp api:9090 --tcp api:9091 > "$OUT/probe-in-worker.json"
cat "$OUT/probe-in-worker.json"

echo "== 5. does the probe use api's resolv.conf / hosts / hostname files? (compare paths)"
docker run --name netdoctor-spike-pathcheck --label "$SPIKE_LABEL" \
  --network container:netdoctor-spike-api "$SPIKE_IMG" report >/dev/null
for c in netdoctor-spike-api netdoctor-spike-pathcheck; do
  docker inspect -f '{{.Name}}: resolv={{.ResolvConfPath}} hosts={{.HostsPath}} hostname={{.HostnamePath}}' "$c"
done

echo "== 6. the distroless problem: docker exec has no tools to run"
docker exec netdoctor-spike-api ss -ltn 2>&1 | head -2 || true

echo "== 7. joining the netns of a stopped container"
docker stop -t 1 netdoctor-spike-worker >/dev/null
docker run "${PROBE[@]}" --network container:netdoctor-spike-worker "$SPIKE_IMG" report 2>&1 | grep -m1 -i 'error' || true

echo "== 8. import time for a realistic binary size (+15 MB of incompressible padding)"
head -c 15000000 /dev/urandom > "$OUT/rootfs/pad"
tar -C "$OUT/rootfs" -cf "$OUT/big.tar" probe pad
t0=$(now_ms)
docker import --change 'ENTRYPOINT ["/probe"]' --change "LABEL $SPIKE_LABEL" "$OUT/big.tar" "$SPIKE_BIG_IMG" >/dev/null
echo "~18 MB import: $(( $(now_ms) - t0 )) ms"
t0=$(now_ms)
docker image inspect "$SPIKE_IMG" >/dev/null
echo "image-exists check: $(( $(now_ms) - t0 )) ms"
