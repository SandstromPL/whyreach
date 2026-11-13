#!/usr/bin/env bash
# Experiments for INITIAL.md §10 Q13–Q15, run before the owner decides them.
# Results: docs/research/q13-q15-experiments.md.
#
#   E1 (Q13): what whyreach does when a container's first DNS server is
#       link-local: on the default bridge (resolv.conf lists it) and on a
#       user-defined network (resolv.conf lists Docker's DNS, which forwards
#       to it). Nothing is sent to the link-local address.
#   E2 (Q14): whether repeated lookups of one name reach the domain's own
#       DNS server every time (TTL 0 and 60): through Docker's DNS on a
#       user-defined network, and directly from the default bridge.
#   E3 (Q15): what limiting TCP probes to loopback and Docker's networks does
#       to a container that reaches a published port through the host's
#       LAN address (published on all addresses, and on 127.0.0.1 only).
#
# Creates only whyreach-spike-* images and whyreach-exp-* containers and
# networks labeled io.whyreach.spike=1, plus whyreach's own probe containers
# and probe image (io.whyreach.probe=1). It removes all of them on exit.
# E3 publishes two inert listeners on the host's LAN address for a few
# seconds. Raw output goes to spikes/out/q13q15/ (git ignores spikes/out).
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=spikes/lib.sh
source spikes/lib.sh

R="$PWD/$OUT/q13q15" # absolute: whyreach ignores relative XDG paths, as the spec says
DNS_IMG=whyreach-spike-dnscount:dev
# E3's servers: the lab's server holds a connection open, as a real service
# does (the spike probe's serve closes each one at once, which whyreach
# reports as "accepted and closed").
SERVER_IMG=whyreach-spike-labserver:dev
NET=whyreach-exp-q1315
PROBE_IMAGES_BEFORE=$(docker images -q --filter "label=$PROBE_LABEL" | sort -u)

cleanup() {
  spike_cleanup
  docker image rm -f "$DNS_IMG" "$SERVER_IMG" >/dev/null 2>&1 || true
  # whyreach imports its own probe image and never deletes images: remove
  # only the ones this run imported.
  comm -13 <(echo "$PROBE_IMAGES_BEFORE") <(docker images -q --filter "label=$PROBE_LABEL" | sort -u) |
    xargs -r docker image rm -f >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$R" && mkdir -p "$R" "$OUT/rootfs-dns"

build_probe_image
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$OUT/rootfs-dns/dnscount" ./spikes/dnscount
tar -C "$OUT/rootfs-dns" -cf "$OUT/dnscount.tar" dnscount
docker import --change 'ENTRYPOINT ["/dnscount"]' --change "LABEL $SPIKE_LABEL" \
  "$OUT/dnscount.tar" "$DNS_IMG" >/dev/null
mkdir -p "$OUT/rootfs-server"
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$OUT/rootfs-server/labserver" ./test/labserver
tar -C "$OUT/rootfs-server" -cf "$OUT/labserver.tar" labserver
docker import --change 'ENTRYPOINT ["/labserver"]' --change "LABEL $SPIKE_LABEL" \
  "$OUT/labserver.tar" "$SERVER_IMG" >/dev/null

# whyreach under test, with config, state and data of its own.
CGO_ENABLED=0 go build -trimpath -o "$R/whyreach" ./cmd/whyreach
X="$R/xdg"
mkdir -p "$X/probe/whyreach" "$X/narrow/whyreach" "$X/state" "$X/data"
printf '[permissions]\nprobe_containers = true\n' >"$X/probe/whyreach/config.toml"
printf '[permissions]\nprobe_containers = true\n\n[probe]\nallow = ["loopback", "docker"]\n' \
  >"$X/narrow/whyreach/config.toml"
wr() { # wr CONFIG ARGS...: run whyreach with that config
  local cfg=$1
  shift
  XDG_CONFIG_HOME="$X/$cfg" XDG_STATE_HOME="$X/state" XDG_DATA_HOME="$X/data" "$R/whyreach" "$@"
}
# One line per evidence record of a `probe --json` result.
probe_summary() {
  jq -r '.evidence[] | "    \(.kind) \(.status) via=\(.data.via // "-") server=\(.data.server // "-") answers=\(.data.answers // [] | join(","))\(if .error then " error=" + (.error | tostring) else "" end)\(if .err then " err=" + (.err | tostring) else "" end)"' "$1"
}
diag_summary() {
  jq -r '"    verdict=\(.verdict) primary=\(.findings[0].rule_id // "-") \(.findings[0].confidence // "")\n    summary: \(.summary)" + ([.gaps[]? | "\n    gap: \(.what): \(.why)"] | join(""))' "$1"
}
run() { docker run -d --label "$SPIKE_LABEL" "$@" >/dev/null; }
docker network create --label "$SPIKE_LABEL" "$NET" >/dev/null

echo "== E1 (Q13): a link-local first DNS server"
run --name whyreach-exp-e1-bridge --dns 169.254.1.1 "$SPIKE_IMG" serve 0.0.0.0:7000
run --name whyreach-exp-e1-udn --network "$NET" --dns 169.254.1.1 "$SPIKE_IMG" serve 0.0.0.0:7000
run --name whyreach-exp-e1-peer --network "$NET" --network-alias peer "$SPIKE_IMG" serve 0.0.0.0:7000
echo "  default bridge, outside name (lookup must not be sent):"
wr probe probe dns example.invalid --from container:whyreach-exp-e1-bridge --json >"$R/e1-bridge-probe.json" 2>"$R/e1-bridge-probe.err"
probe_summary "$R/e1-bridge-probe.json"
echo "  default bridge, diagnose example.invalid:443:"
wr probe diagnose --from container:whyreach-exp-e1-bridge example.invalid:443 >"$R/e1-bridge-diag.txt" 2>&1
sed 's/^/    | /' "$R/e1-bridge-diag.txt"
echo "  user-defined network, a name Docker knows (answered by Docker's DNS, not forwarded):"
wr probe probe dns peer --from container:whyreach-exp-e1-udn --json >"$R/e1-udn-probe.json" 2>"$R/e1-udn-probe.err"
probe_summary "$R/e1-udn-probe.json"

echo "== E2 (Q14): do repeated lookups reach the domain's server?"
run --name whyreach-exp-dns-udn --network "$NET" "$DNS_IMG"
run --name whyreach-exp-dns-bridge "$DNS_IMG"
D1=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" whyreach-exp-dns-udn)
D2=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' whyreach-exp-dns-bridge)
run --name whyreach-exp-e2-udn --network "$NET" --dns "$D1" "$SPIKE_IMG" serve 0.0.0.0:7000
run --name whyreach-exp-e2-bridge --dns "$D2" "$SPIKE_IMG" serve 0.0.0.0:7000
N=10
for path in udn bridge; do
  for ttl in ttl0 ttl60; do
    name="n-$path.$ttl.test"
    t0=$(now_ms)
    for i in $(seq 1 $N); do
      wr probe probe dns "$name" --from "container:whyreach-exp-e2-$path" --json >"$R/e2-$path-$ttl-$i.json" 2>/dev/null
    done
    secs=$(( ($(now_ms) - t0) / 1000 ))
    logs=$(docker logs "whyreach-exp-dns-$path" 2>/dev/null)
    a=$(grep -c " A $name\.$" <<<"$logs")
    aaaa=$(grep -c " AAAA $name\.$" <<<"$logs")
    ok=$(jq -s '[.[].evidence[] | select(.kind == "probe.dns" and .status == "ok")] | length' "$R"/e2-"$path"-"$ttl"-*.json)
    echo "  $path $ttl: $N lookups in ${secs}s ($ok answered); the server saw $a A and $aaaa AAAA queries"
  done
done
probe_summary "$R/e2-udn-ttl0-1.json"
probe_summary "$R/e2-bridge-ttl0-1.json"

echo "== E3 (Q15): a container reaching a published port through the host's LAN address"
LAN=$(ip -4 route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
echo "  host LAN address: <host-lan-ip> (not printed)"
# api-same shares the client's network, api-other is on the default bridge,
# api-lo publishes on the host's loopback only.
run --name whyreach-exp-e3-api-same --network "$NET" -p "$LAN:18080:8080" "$SERVER_IMG" serve 0.0.0.0:8080
run --name whyreach-exp-e3-api-other -p "$LAN:18082:8080" "$SERVER_IMG" serve 0.0.0.0:8080
run --name whyreach-exp-e3-api-lo -p 127.0.0.1:18081:8080 "$SERVER_IMG" serve 0.0.0.0:8080
run --name whyreach-exp-e3-client --network "$NET" "$SPIKE_IMG" serve 0.0.0.0:7000
describe() {
  case $1 in
  18080) echo "published on the LAN address, server on the client's network" ;;
  18082) echo "published on the LAN address, server on the default bridge" ;;
  18081) echo "published on 127.0.0.1 only" ;;
  esac
}
for cfg in probe narrow; do
  for port in 18080 18082 18081; do
    f="$R/e3-$cfg-$port.json"
    wr "$cfg" diagnose --from container:whyreach-exp-e3-client "$LAN:$port" --json >"$f" 2>"$R/e3-$cfg-$port.err"
    echo "  allow=$([ $cfg = narrow ] && echo 'loopback,docker' || echo 'default (loopback,rfc1918,docker)'), $(describe $port):"
    diag_summary "$f" | sed "s/$LAN/<host-lan-ip>/g"
  done
done
echo "== done; raw output in $R"
