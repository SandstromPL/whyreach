# Shared helpers for the M0 spike scripts. Source it from the repo root; don't run it.
# shellcheck shell=bash

SPIKE_LABEL=io.whyreach.spike=1
PROBE_LABEL=io.whyreach.probe=1
SPIKE_IMG=whyreach-spike-probe:dev
SPIKE_BIG_IMG=whyreach-spike-big:dev
SPIKE_NET=whyreach-spike-net
OUT=spikes/out

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

# Remove only what the spikes created (by label and exact image names).
spike_cleanup() {
  docker ps -aq --filter "label=$SPIKE_LABEL" | xargs -r docker rm -f >/dev/null
  docker ps -aq --filter "label=$PROBE_LABEL" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=$SPIKE_LABEL" | xargs -r docker network rm >/dev/null
  docker image rm -f "$SPIKE_IMG" "$SPIKE_BIG_IMG" >/dev/null 2>&1 || true
}

# Build the static probe and import it as a FROM-scratch image (no registry pull).
# Sets IMPORT_MS and PROBE_BYTES.
build_probe_image() {
  mkdir -p "$OUT/rootfs"
  CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$OUT/rootfs/probe" ./spikes/probe
  tar -C "$OUT/rootfs" -cf "$OUT/probe.tar" probe
  local t0
  t0=$(now_ms)
  docker import --change 'ENTRYPOINT ["/probe"]' --change "LABEL $SPIKE_LABEL" \
    "$OUT/probe.tar" "$SPIKE_IMG" >/dev/null
  IMPORT_MS=$(( $(now_ms) - t0 ))
  PROBE_BYTES=$(stat -c %s "$OUT/rootfs/probe")
}

# Two "distroless" services on a user-defined network:
#   api    listens on 127.0.0.1:8080 (loopback only), 0.0.0.0:9090 and [::]:9091
#   worker listens on 0.0.0.0:7000
# api also gets an extra hosts entry and a DNS search domain, used as markers.
start_services() {
  docker network create --label "$SPIKE_LABEL" "$SPIKE_NET" >/dev/null
  docker run -d --name whyreach-spike-api --label "$SPIKE_LABEL" \
    --network "$SPIKE_NET" --network-alias api \
    --add-host spike-extra:10.9.8.7 --dns-search spike.example \
    "$SPIKE_IMG" serve 127.0.0.1:8080 0.0.0.0:9090 '[::]:9091' >/dev/null
  docker run -d --name whyreach-spike-worker --label "$SPIKE_LABEL" \
    --network "$SPIKE_NET" \
    "$SPIKE_IMG" serve 0.0.0.0:7000 >/dev/null
}
