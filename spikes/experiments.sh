#!/usr/bin/env bash
# Rule-detectability experiments (between M0 and M1).
#
# Reproduces the most frequent real-world failures from docs/research/failure-signatures.md
# and prints what whyreach could observe from its three vantage points:
#   1. Docker API metadata (docker inspect)
#   2. listeners read from the host through /proc/<pid>/net/tcp (no root)
#   3. probes run inside the right container's network namespace (hardened probe container)
#
# Creates only whyreach-exp-* / whyreach-spike-* resources, plus two short-lived host
# listeners on 127.0.0.1 and the docker0 address. Everything is removed on exit.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=spikes/lib.sh
source spikes/lib.sh
EXP=spikes/experiments
R=$OUT/exp
mkdir -p "$R"
BIN=$OUT/rootfs/probe
PROJECTS=(e1 e2a e2b e3 e4 e5 e6 e8)
host_pid=""

exp_cleanup() {
  [ -n "$host_pid" ] && kill "$host_pid" 2>/dev/null
  for p in "${PROJECTS[@]}"; do
    docker compose -p "whyreach-exp-$p" -f "$EXP/$p.yaml" down -v --remove-orphans >/dev/null 2>&1
  done
  spike_cleanup
}
trap exp_cleanup EXIT
exp_cleanup

P=(--rm --label "$PROBE_LABEL" --cap-drop ALL --user 65534:65534 --read-only
   --security-opt no-new-privileges --pids-limit 32 --memory 32m)

up()    { docker compose -p "whyreach-exp-$1" -f "$EXP/$1.yaml" up -d >/dev/null 2>"$R/$1-up.log" || cat "$R/$1-up.log"; }
down()  { docker compose -p "whyreach-exp-$1" -f "$EXP/$1.yaml" down -v --remove-orphans >/dev/null 2>&1; }
cname() { echo "whyreach-exp-$1-$2-1"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" | awk '{print $1}'; }
summ()  { python3 -I "$EXP/summarize.py" "$@"; }

# probe_in LABEL CONTAINER REPORT-ARGS...  (probe container joined to CONTAINER's netns)
probe_in() {
  local label=$1 c=$2
  shift 2
  docker run "${P[@]}" --network "container:$c" "$SPIKE_IMG" report "$@" >"$R/$label.json" 2>"$R/$label.err"
  summ probe "$R/$label.json" "$R/$label.err" "$label"
}
# listeners LABEL CONTAINER  (read from the host via /proc/<pid>/net/tcp{,6}, no root)
listeners() {
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' "$2")
  if [ "$pid" = 0 ]; then echo "  [$1] listeners: container not running (pid 0)"; return; fi
  "$BIN" report --proc-dir "/proc/$pid" >"$R/$1.json" 2>"$R/$1.err"
  summ listeners "$R/$1.json" "$R/$1.err" "$1"
}
brief() {
  for c in "$@"; do
    docker inspect -f '  [{{.Name}}] status={{.State.Status}}{{if .State.Health}} health={{.State.Health.Status}}{{end}} restarts={{.RestartCount}} exit={{.State.ExitCode}} started={{.State.StartedAt}}
      nets={{range $k, $v := .NetworkSettings.Networks}}{{$k}}:{{$v.IPAddress}}{{if $v.DNSNames}}[{{join $v.DNSNames ","}}]{{end}} {{end}}ports={{json .HostConfig.PortBindings}} extra_hosts={{json .HostConfig.ExtraHosts}} project={{index .Config.Labels "com.docker.compose.project"}}' "$c"
  done
}

echo "== build the probe image (FROM scratch, no pull)"
build_probe_image
echo "  now: $(date -u +%FT%TZ)"

echo
echo "== E1 localhost inside a container (WR007), loopback-only bind (WR002), typo (WR005), IPv6 localhost (WR014)"
up e1
brief "$(cname e1 app)" "$(cname e1 db)"
listeners e1-db "$(cname e1 db)"
listeners e1-app "$(cname e1 app)"
probe_in e1-from-app "$(cname e1 app)" --dns localhost --dns db --dns dbb \
  --tcp localhost:5432 --tcp db:5432 --tcp db:9000
down e1

echo
echo "== E2 separate Compose projects (WR004)"
up e2a
up e2b
brief "$(cname e2a api)" "$(cname e2b worker)"
api_ip=$(ip_of "$(cname e2a api)")
probe_in e2-from-worker "$(cname e2b worker)" --timeout 3s --dns api --tcp api:8080 --tcp "$api_ip:8080"
down e2a
down e2b

echo
echo "== E3 upstream DNS unreachable (candidate WR020)"
up e3
probe_in e3-from-client "$(cname e3 client)" --timeout 6s --dns peer --dns example.com --tcp 1.1.1.1:443
summ resolv "$R/e3-from-client.json" "" e3-client
probe_in e3-control-from-peer "$(cname e3 peer)" --timeout 6s --dns example.com
summ resolv "$R/e3-control-from-peer.json" "" e3-peer
docker run -d --name whyreach-exp-e3-bridge --label "$SPIKE_LABEL" --dns 192.0.2.53 "$SPIKE_IMG" serve 0.0.0.0:7000 >/dev/null
probe_in e3-default-bridge whyreach-exp-e3-bridge --timeout 6s --dns example.com
summ resolv "$R/e3-default-bridge.json" "" e3-default-bridge
docker rm -f whyreach-exp-e3-bridge >/dev/null
down e3

echo
echo "== E4 slow start (WR010) and crash loop (WR008)"
up e4
echo "  -- right after start"
brief "$(cname e4 slow)" "$(cname e4 crashy)"
listeners e4-slow-early "$(cname e4 slow)"
probe_in e4-early "$(cname e4 client)" --tcp slow:8080
echo "  -- joining the crash-looping container's netns:"
docker run "${P[@]}" --network "container:$(cname e4 crashy)" "$SPIKE_IMG" report 2>&1 >/dev/null | grep -m1 -i error | sed 's/^/  /'
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(cname e4 slow)")" = healthy ] && break
  sleep 0.5
done
echo "  -- after the slow service became healthy"
brief "$(cname e4 slow)" "$(cname e4 crashy)"
listeners e4-slow-late "$(cname e4 slow)"
probe_in e4-late "$(cname e4 client)" --tcp slow:8080
down e4

echo
echo "== E5 host services: host.docker.internal (WR011), host service bound to loopback (WR012)"
gw=$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)
"$BIN" serve 127.0.0.1:18432 "$gw:18433" &
host_pid=$!
up e5
brief "$(cname e5 nohg)" "$(cname e5 hg)"
echo "  host listeners on 18432-18434 (read from /proc/net/tcp, no root):"
"$BIN" report >"$R/e5-host.json" && python3 -I -c 'import json,sys; print("   ", [s["local"] for s in json.load(open(sys.argv[1]))["listeners"] if s["local"].rsplit(":",1)[1] in ("18432","18433","18434")])' "$R/e5-host.json"
probe_in e5-from-nohg "$(cname e5 nohg)" --dns host.docker.internal
probe_in e5-from-hg "$(cname e5 hg)" --timeout 3s --dns host.docker.internal \
  --tcp host.docker.internal:18432 --tcp host.docker.internal:18433 --tcp host.docker.internal:18434
kill "$host_pid" 2>/dev/null
host_pid=""
down e5

echo
echo "== E6 publishing ports (candidate WR019, WR006)"
up e6
brief "$(cname e6 web)" "$(cname e6 weblo)"
"$BIN" report --timeout 2s --tcp 127.0.0.1:8080 --tcp 127.0.0.1:18090 --tcp "$gw:18090" >"$R/e6-from-host.json" 2>"$R/e6-from-host.err"
summ probe "$R/e6-from-host.json" "$R/e6-from-host.err" e6-from-host
python3 -I -c 'import json,sys; print("  [e6-host] listeners on 18090:", [s["local"] for s in json.load(open(sys.argv[1]))["listeners"] if s["local"].endswith(":18090")])' "$R/e6-from-host.json"
probe_in e6-from-client "$(cname e6 client)" --tcp weblo:18090 --tcp weblo:8080 --tcp web:8080
down e6

echo
echo "== E7 default bridge network: no name resolution (WR009)"
docker run -d --name whyreach-exp-e7-a --label "$SPIKE_LABEL" "$SPIKE_IMG" serve 0.0.0.0:8080 >/dev/null
docker run -d --name whyreach-exp-e7-b --label "$SPIKE_LABEL" "$SPIKE_IMG" serve 0.0.0.0:7000 >/dev/null
brief whyreach-exp-e7-a
probe_in e7-from-b whyreach-exp-e7-b --dns whyreach-exp-e7-a --tcp "$(ip_of whyreach-exp-e7-a):8080"
summ resolv "$R/e7-from-b.json" "" e7-b
docker rm -f whyreach-exp-e7-a whyreach-exp-e7-b >/dev/null

echo
echo "== E8 path failures: internal network (WR015), black hole (WR016), unused address on the subnet"
up e8
probe_in e8-from-isolated "$(cname e8 isolated)" --timeout 3s --tcp 1.1.1.1:443
subnet=$(docker network inspect whyreach-exp-e8_default -f '{{(index .IPAM.Config 0).Subnet}}')
unused=$(python3 -I -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(n.network_address+200)' "$subnet")
probe_in e8-from-normal "$(cname e8 normal)" --timeout 6s --tcp 192.0.2.1:80 --tcp "$unused:80"

echo
echo "== E9 host observations: route lookup into a Docker subnet (WR013), MTUs (WR017)"
echo "  route to unused $unused: $(ip route get "$unused" | head -1 | grep -o 'dev [^ ]*')"
br="br-$(docker network inspect whyreach-exp-e8_default -f '{{.Id}}' | cut -c1-12)"
egress=$(ip route get 1.1.1.1 | grep -o 'dev [^ ]*' | cut -d' ' -f2)
echo "  MTU: docker bridge $(cat "/sys/class/net/$br/mtu"), default egress interface $(cat "/sys/class/net/$egress/mtu")"
down e8

echo
echo "== leftovers after cleanup run on exit (checked by the caller)"
