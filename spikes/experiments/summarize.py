"""Print a compact view of a probe report (spikes/probe `report` JSON).

Usage: summarize.py MODE JSON_PATH ERR_PATH LABEL
  MODE = probe      DNS and TCP results
         listeners  listening sockets (Docker's embedded-DNS listener hidden)
         resolv     resolver lines from the probe's resolv.conf (search domain hidden)
"""
import json
import sys

mode, path, err_path, label = sys.argv[1:5]
try:
    with open(path) as f:
        data = json.load(f)
except (OSError, ValueError) as exc:
    err = ""
    if err_path:
        try:
            with open(err_path) as f:
                err = f.read().strip()
        except OSError:
            pass
    print(f"  [{label}] probe failed: {(err or str(exc))[:240]}")
    sys.exit(0)

if mode == "listeners":
    socks = [s["local"] for s in data.get("listeners") or [] if not s["local"].startswith("127.0.0.11:")]
    print(f"  [{label}] listeners: {', '.join(socks) or '(none)'}")
elif mode == "resolv":
    keep = [l.strip() for l in data.get("resolv_conf", "").splitlines()
            if l.startswith(("nameserver", "options", "# ExtServers"))]
    print(f"  [{label}] resolv.conf: {' | '.join(keep)}")
else:
    for r in data.get("dns") or []:
        ans = ",".join(r.get("addrs") or []) or r.get("error", "")
        print(f"  [{label}] dns {r['name']}: {r['outcome']} {ans[:110]} ({r.get('ms', 0):.0f} ms)")
    for r in data.get("tcp") or []:
        print(f"  [{label}] tcp {r['target']} -> {r.get('addr', '')}: {r['outcome']} "
              f"{r.get('error', '')[-55:]} ({r['rtt_ms']:.1f} ms)")
