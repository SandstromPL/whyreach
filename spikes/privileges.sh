#!/usr/bin/env bash
# M0 spike: what can a docker-group user (no root) see about a container's network?
# Answers INITIAL.md §10 Q1. Every check is a read attempt; creates only whyreach-spike-* resources.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=spikes/lib.sh
source spikes/lib.sh
mkdir -p "$OUT"
trap spike_cleanup EXIT
spike_cleanup
build_probe_image
start_services

pid=$(docker inspect -f '{{.State.Pid}}' whyreach-spike-api)
cid=$(docker inspect -f '{{.Id}}' whyreach-spike-api)
in_docker=$(id -nG | tr ' ' '\n' | grep -qx docker && echo yes || echo no)
echo "uid=$(id -u) (root: $([ "$(id -u)" = 0 ] && echo yes || echo no)), docker group: $in_docker, target pid=$pid"
echo

# check DESCRIPTION CMD...  → OK/DENIED plus the first line of output
check() {
  local desc=$1 out
  shift
  if out=$("$@" 2>&1); then
    printf '%-48s OK      %s\n' "$desc" "$(head -1 <<<"$out" | cut -c1-60)"
  else
    printf '%-48s DENIED  %s\n' "$desc" "$(head -1 <<<"$out" | cut -c1-60)"
  fi
}
# checkq: same, but never prints the content (for files that could hold secrets)
checkq() {
  local desc=$1 out
  shift
  if out=$("$@" 2>&1); then printf '%-48s OK\n' "$desc"
  else printf '%-48s DENIED  %s\n' "$desc" "$(head -1 <<<"$out" | cut -c1-60)"; fi
}

echo "--- container netns, read from the host"
check  "read /proc/PID/net/tcp"                  cat "/proc/$pid/net/tcp"
check  "read /proc/PID/net/tcp6"                 cat "/proc/$pid/net/tcp6"
check  "readlink /proc/PID/ns/net"               readlink "/proc/$pid/ns/net"
check  "stat /proc/PID/ns/net (netns inode)"     stat -L -c %i "/proc/$pid/ns/net"
check  "read /proc/PID/root/etc/resolv.conf"     cat "/proc/$pid/root/etc/resolv.conf"
check  "read /proc/PID/cgroup"                   cat "/proc/$pid/cgroup"
check  "list /proc/PID/fd (socket -> process)"   ls "/proc/$pid/fd"
checkq "read /proc/PID/environ"                  cat "/proc/$pid/environ"
check  "nsenter --net (setns)"                   nsenter -t "$pid" -n true

echo "--- host"
check  "netlink link dump (ip -br link)"         ip -br link
check  "route lookup (ip route get 1.1.1.1)"     ip route get 1.1.1.1
check  "read /proc/net/tcp"                      cat /proc/net/tcp
check  "nftables ruleset (nft list ruleset)"     nft list ruleset
check  "iptables rules (iptables -S)"            iptables -S
check  "Docker API (GET /version)"               docker version --format '{{.Server.APIVersion}}'
printf '%-48s %s\n' "unprivileged ICMP (ping_group_range)" "$(cat /proc/sys/net/ipv4/ping_group_range)"
printf '%-48s %s of %s listeners show a process\n' "ss -ltnp process info" \
  "$(ss -Hltnp | grep -c 'users:' || true)" "$(ss -Hltn | wc -l)"

echo
echo "--- detail: decode the container's listeners from the host, without root"
"$OUT/rootfs/probe" report --proc-dir "/proc/$pid" | grep -A3 '"proto"' | grep -E '"(proto|local|state)"' | paste - - - || true
echo "--- detail: does /proc/PID/cgroup name the container? (PID-identity check for the netns executor)"
if grep -q "$cid" "/proc/$pid/cgroup" 2>/dev/null; then echo "yes: $(grep -o "docker-[0-9a-f]\{12\}" "/proc/$pid/cgroup" | head -1)…"; else echo "no"; fi
