#!/usr/bin/env python3
"""Make docs/assets/benchmark-light.svg and benchmark-dark.svg, the README's benchmark chart.

The numbers come from docs/research/agent-benchmark/results.json, the recorded run
of `make lab-bench`. Run it from the repository root after a new recorded run:

    python3 docs/assets/make_benchmark_chart.py

The README shows the light or the dark file to match the reader's GitHub theme.
"""

import json
from xml.sax.saxutils import escape

RESULTS = "docs/research/agent-benchmark/results.json"
FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"

# The page behind the chart is GitHub's; the shell agent is the gray context and
# whyreach the one accent hue. Checked for contrast and colour-blind separation.
THEMES = {
    "light": dict(surface="#ffffff", primary="#0b0b0b", secondary="#52514e", muted="#898781",
                  baseline="#c3c2b7", shell="#898781", whyreach="#2a78d6"),
    "dark": dict(surface="#0d1117", primary="#f0efec", secondary="#c3c2b7", muted="#898781",
                 baseline="#383835", shell="#898781", whyreach="#3987e5"),
}

W = 720
PAD = 24
LABEL_W = 210        # the metric names' column
BAR_X = PAD + LABEL_W
BAR_MAX = 380        # the longest bar; its value label goes after it
BAR_H = 16
BAR_GAP = 6
ROW_GAP = 24
TOP = 132            # where the first row starts


def rows():
    data = json.load(open(RESULTS))
    s, runs = data["summary"], data["runs"]
    n = s["scenarios"]

    def tried(arm):
        mine = [r for r in runs if r["arm"] == arm]
        return sum(1 for r in mine if r["unsafe"])

    unsafe = [u["command"] for r in runs for u in (r["unsafe"] or [])]
    label = "Runs that tried docker exec" if all("docker exec" in c for c in unsafe) \
        else "Runs with an unsafe command"
    return n, s, [
        ("Tool calls, median", s["median_calls_shell"], s["median_calls_whyreach"], None, str),
        ("Tokens, median", s["median_tokens_shell"], s["median_tokens_whyreach"], None,
         lambda v: f"{v / 1000:.1f}k"),
        ("Time, median", s["median_seconds_shell"], s["median_seconds_whyreach"], None,
         lambda v: f"{v:.1f} s"),
        (label, tried("shell"), tried("whyreach"), n, lambda v: f"{v} of {n}"),
    ]


def bar(x, y, w, color):
    """A bar from the baseline, square there and rounded (4px) at its data end."""
    if w <= 0:
        return ""
    r = min(4, w)
    return (f'<path d="M{x},{y} H{x + w - r:.1f} A{r},{r} 0 0 1 {x + w:.1f},{y + r} '
            f'V{y + BAR_H - r} A{r},{r} 0 0 1 {x + w - r:.1f},{y + BAR_H} H{x} Z" fill="{color}"/>')


def text(x, y, s, size, color, weight=400, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color}" '
            f'text-anchor="{anchor}">{escape(s)}</text>')


def svg(theme):
    t = THEMES[theme]
    n, s, data = rows()
    title = "An AI agent with a shell vs one with whyreach"
    subtitle = (f"Claude Haiku on {n} Docker networking scenarios. "
                f"Both named the right cause in {s['right_whyreach']} of {n}."
                if s["right_shell"] == s["right_whyreach"] else
                f"Claude Haiku on {n} Docker networking scenarios. Right causes: shell "
                f"{s['right_shell']} of {n}, whyreach {s['right_whyreach']} of {n}.")
    row_h = 2 * BAR_H + BAR_GAP + ROW_GAP
    h = TOP + len(data) * row_h + 28
    desc = "; ".join(f"{name}: shell agent {fmt(a)}, whyreach agent {fmt(b)}" for name, a, b, _, fmt in data)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" '
        f'font-family="{FONT}" role="img" aria-labelledby="t d">',
        f'<title id="t">{escape(title)}</title>',
        f'<desc id="d">{escape(subtitle + " " + desc + ".")}</desc>',
        f'<rect width="{W}" height="{h}" rx="8" fill="{t["surface"]}"/>',
        text(PAD, 40, title, 20, t["primary"], 600),
        text(PAD, 64, subtitle, 14, t["secondary"]),
    ]
    # the legend: always present for two series
    lx = PAD
    for name, color in (("Agent with a shell", t["shell"]), ("Agent with whyreach", t["whyreach"])):
        out.append(f'<rect x="{lx}" y="88" width="12" height="12" rx="3" fill="{color}"/>')
        out.append(text(lx + 18, 99, name, 14, t["secondary"]))
        lx += 18 + len(name) * 8 + 24
    top = TOP
    out.append(f'<line x1="{BAR_X - 0.5}" y1="{top - 8}" x2="{BAR_X - 0.5}" '
               f'y2="{top + len(data) * row_h - ROW_GAP + 8}" stroke="{t["baseline"]}" stroke-width="1"/>')
    for name, a, b, scale, fmt in data:
        scale = scale or max(a, b)
        mid = top + BAR_H + BAR_GAP / 2
        out.append(text(PAD, mid + 5, name, 14, t["primary"], 500))
        for i, (v, color, ink, weight) in enumerate(((a, t["shell"], t["secondary"], 400),
                                                     (b, t["whyreach"], t["primary"], 600))):
            y = top + i * (BAR_H + BAR_GAP)
            w = BAR_MAX * v / scale if scale else 0
            out.append(bar(BAR_X, y, round(w, 1), color))
            out.append(text(round(BAR_X + w + 8, 1), y + BAR_H - 3, fmt(v), 13, ink, weight))
        top += row_h
    out.append(text(PAD, h - 16, "Medians are per scenario. Method and raw data: "
                    "docs/research/agent-benchmark.md", 12, t["muted"]))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    for theme in THEMES:
        path = f"docs/assets/benchmark-{theme}.svg"
        with open(path, "w") as f:
            f.write(svg(theme))
        print(path)


if __name__ == "__main__":
    main()
