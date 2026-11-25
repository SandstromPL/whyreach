#!/usr/bin/env python3
"""Merge the labelers' files into labels.yaml (docs/research/real-cases.md).

Walks each pool in its shuffled order and takes the first cases labelled
`in` until the source's quota is filled: those are the sample. Every case
looked at up to the last one taken is kept, with its label, so the
exclusions show; cases labelled in parallel past that point are counted,
not listed.

    python3 docs/research/real-cases/labels.py
"""

import json
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
LABELS = HERE.parents[2] / "bin" / "realcases" / "labels"
QUOTAS = {"stackoverflow": 12, "forum": 4, "github": 4}
FIELDS = ["case", "decision", "out_reason", "cause", "connection", "rule", "planned_rule", "also", "fix",
          "fix_source", "needs_other_image", "label_confidence", "notes"]


def main():
    labelled = {}
    for f in sorted(LABELS.glob("*.yaml")):
        for entry in yaml.safe_load(f.read_text()) or []:
            labelled[entry["case"]] = entry
    out, unused = [], {}
    for source, quota in QUOTAS.items():
        order = json.loads((HERE / f"pool-{source}.json").read_text())["order"]
        taken, last = 0, 0
        for pos, c in enumerate(order, start=1):
            if taken == quota:
                break
            label = labelled.get(c["id"])
            if label is None:
                raise SystemExit(f"{c['id']} (#{pos} in {source}) isn't labelled yet")
            entry = {"source": source, "position": pos, "url": c["url"]}
            entry |= {k: label[k] for k in FIELDS if label.get(k) not in (None, "", [])}
            entry["selected"] = label["decision"] == "in"
            taken += entry["selected"]
            last = pos
            out.append(entry)
        unused[source] = sum(1 for c in order[last:] if c["id"] in labelled)
        if taken < quota:
            print(f"{source}: only {taken} of {quota} cases in the labelled part of the pool")
    doc = {"quotas": QUOTAS, "labelled_past_the_quota": unused, "cases": out}
    (HERE / "labels.yaml").write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100))
    for source in QUOTAS:
        sel = [e for e in out if e["source"] == source and e["selected"]]
        print(source, "looked at", sum(e["source"] == source for e in out), "selected", len(sel),
              [f"{e['case']}:{e.get('rule')}" for e in sel])


if __name__ == "__main__":
    main()
