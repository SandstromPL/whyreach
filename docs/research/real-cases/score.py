#!/usr/bin/env python3
"""Score the real-case check (docs/research/real-cases.md, "Scoring").

Reads the labels (docs/research/real-cases/labels.yaml) and what whyreach
said (bin/realcases/results.json, from make lab-realcases), and writes
docs/research/real-cases/scores.json and table.md. The rules, fixed before
the run:
- right: the primary finding is the labelled rule;
- partly right: the labelled rule is only among the other findings;
- inconclusive: no cause named; right for an `outside` case, a miss for a
  covered one;
- wrong: a cause other than the label (for an `outside` case, any cause).
`ambiguous` labels are reported, not scored.

    python3 docs/research/real-cases/score.py [results.json]
"""

import json
import sys
from collections import Counter
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CONFIGS = ["probe-containers", "default-config"]


def outcome(label, run):
    findings = run.get("findings") or []
    primary = findings[0]["rule"] if findings else None
    rule = label["rule"]
    if rule == "outside":
        return ("inconclusive-right", None) if primary is None else ("wrong", findings[0]["confidence"])
    if primary is None:
        return "inconclusive", None
    if primary == rule:
        return "right", findings[0]["confidence"]
    if any(f["rule"] == rule for f in findings[1:]):
        return "partly", findings[0]["confidence"]
    return "wrong", findings[0]["confidence"]


def main():
    results_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parents[2] / "bin" / "realcases" / "results.json"
    labels = {l["case"]: l for l in yaml.safe_load((HERE / "labels.yaml").read_text())["cases"]}
    results = {r["case"]: r for r in json.loads(results_path.read_text())["cases"]}
    rows, tally = [], {c: Counter() for c in CONFIGS}
    for case, label in labels.items():
        if not label.get("selected"):
            continue
        r = results.get(case)
        row = {"case": case, "label": label["rule"]}
        if r is None:
            row["status"] = "not run"
        elif r.get("error"):
            row["status"] = "error: " + r["error"]
        elif not r["symptom"]["match"]:
            row["status"] = f"not reproduced (wanted {r['symptom']['want']}, got {r['symptom']['got']})"
        elif label["rule"] == "ambiguous":
            row["status"] = "ambiguous label: not scored"
        else:
            row["status"] = "scored"
            for run in r["runs"]:
                o, conf = outcome(label, run)
                f = run.get("findings") or []
                row[run["config"]] = {"outcome": o, "said": f"{f[0]['rule']} ({f[0]['confidence']})" if f else run["verdict"],
                                      "also": [x["rule"] for x in f[1:]]}
                key = o + ("-high" if o == "wrong" and conf == "high" else "")
                tally[run["config"]][key] += 1
                tally[run["config"]]["covered" if label["rule"] != "outside" else "outside"] += 1
        rows.append(row)
    summary = {c: dict(sorted(tally[c].items())) for c in CONFIGS}
    (HERE / "scores.json").write_text(json.dumps({"summary": summary, "cases": rows}, indent=1) + "\n")
    lines = ["| Case | Label | Probe containers on | Default config | Status |", "|---|---|---|---|---|"]
    for row in rows:
        cells = []
        for c in CONFIGS:
            x = row.get(c)
            cells.append(f"{x['outcome']}: {x['said']}" + (f" (also {', '.join(x['also'])})" if x and x["also"] else "") if x else "")
        lines.append(f"| {row['case']} | {row['label']} | {cells[0]} | {cells[1]} | {row['status']} |")
    (HERE / "table.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
