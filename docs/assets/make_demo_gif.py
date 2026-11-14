#!/usr/bin/env python3
"""Make docs/assets/demo.gif, the README's demo animation, from the demo's real output.

It starts the demo (demo/compose.yaml, Compose project whyreach-demo), records the
real output of two commands, removes the demo, and draws the commands and their
output as a terminal session. Nothing in the output is edited.

Needs Docker, a built bin/whyreach (`make build`), Python 3 with Pillow, and the
DejaVu Sans Mono font. Run it from the repository root:

    make build && python3 docs/assets/make_demo_gif.py

whyreach runs with XDG_CONFIG_HOME=/home/you/.config: it then uses its default
configuration whatever yours says, and the config path it prints shows a neutral
home directory instead of yours.
"""

import argparse
import os
import pathlib
import subprocess
import sys
import time

from PIL import Image, ImageDraw, ImageFont

CMD1 = "docker compose -f demo/compose.yaml logs --tail 1 worker"
CMD2 = "whyreach --from service:worker@whyreach-demo localhost:8080"

S = 2  # drawn at twice the displayed size, so text stays sharp on HiDPI screens
FONT_PX = 14 * S
LINE = round(FONT_PX * 1.45)
PAD_X, PAD_TOP, PAD_BOTTOM, BAR = 18 * S, 14 * S, 16 * S, 30 * S

BG = (17, 22, 29)
BAR_BG = (30, 36, 46)
TEXT = (214, 221, 230)
DIM = (125, 133, 144)
PROMPT = (126, 231, 135)
CMD = (255, 255, 255)
DOTS = [(255, 95, 87), (254, 188, 46), (40, 200, 64)]

TYPE_MS = 40
BLINK_MS = 600


def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


def capture():
    """Start the demo, record both commands' output, and remove the demo."""
    compose = ["docker", "compose", "-f", "demo/compose.yaml"]
    run(compose + ["up", "-d", "--wait"])
    try:
        log = ""
        for _ in range(20):  # the worker logs its first failure right after it starts
            log = run(compose + ["logs", "--tail", "1", "worker"]).rstrip("\n")
            if log:
                break
            time.sleep(0.5)
        env = dict(os.environ, XDG_CONFIG_HOME="/home/you/.config")
        res = subprocess.run(
            ["bin/whyreach", "--from", "service:worker@whyreach-demo", "localhost:8080"],
            env=env, capture_output=True, text=True,
        )
        if res.returncode not in (0, 1) or res.stderr:  # 1: a cause was found
            sys.exit(f"whyreach failed ({res.returncode}): {res.stderr}")
        return log, res.stdout.rstrip("\n").split("\n")
    finally:
        run(compose + ["down"])


def font(bold=False):
    name = "DejaVu Sans Mono:bold" if bold else "DejaVu Sans Mono"
    path = run(["fc-match", "-f", "%{file}", name])
    return ImageFont.truetype(path, FONT_PX)


REG, BOLD = font(), font(bold=True)
SMALL = ImageFont.truetype(run(["fc-match", "-f", "%{file}", "DejaVu Sans Mono"]), 12 * S)
ADV = REG.getlength("M")
ASC, DESC = REG.getmetrics()


def prompt(cmd):
    return [("$ ", PROMPT, BOLD), (cmd, CMD, BOLD)]


def plain(text):
    return [(text, TEXT, REG)]


def draw(rows, cursor, size):
    w, h = size
    im = Image.new("RGB", size, BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, w, BAR], fill=BAR_BG)
    for i, c in enumerate(DOTS):
        cx, cy, r = PAD_X + 6 * S + i * 20 * S, BAR // 2, 6 * S
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=c)
    d.text((w // 2, BAR // 2), "whyreach demo", font=SMALL, fill=DIM, anchor="mm")
    for i, row in enumerate(rows):
        y = BAR + PAD_TOP + i * LINE + (LINE - ASC - DESC) // 2
        x = PAD_X
        for text, color, f in row:
            d.text((x, y), text, font=f, fill=color)
            x += len(text) * ADV
    if cursor:
        r, c = cursor
        x = PAD_X + c * ADV
        y = BAR + PAD_TOP + r * LINE + (LINE - ASC - DESC) // 2
        d.rectangle([x, y, x + ADV - 1, y + ASC + DESC], fill=TEXT)
    return im


def session(log, out):
    """The frames of the terminal session, as (rows, cursor, milliseconds)."""
    seq, hist = [], []

    def typing(cmd):
        for i in range(len(cmd) + 1):
            seq.append((hist + [prompt(cmd[:i])], (len(hist), 2 + i), TYPE_MS))
        seq.append((hist + [prompt(cmd)], (len(hist), 2 + len(cmd)), 450))

    def waiting(blinks):
        for k in range(blinks):
            seq.append((hist + [prompt("")], (len(hist), 2) if k % 2 == 0 else None, BLINK_MS))

    waiting(2)
    typing(CMD1)
    hist += [prompt(CMD1), plain(log)]
    waiting(4)  # time to read "Connection refused"
    typing(CMD2)
    hist += [prompt(CMD2)]
    seq.append((list(hist), None, 700))  # whyreach is running
    hist += [plain(line) for line in out]
    waiting(14)  # time to read the cause and the fix
    return seq, len(hist) + 1


def render(log, out, path):
    cols = max(80, len(log), *(len(line) for line in out), 2 + len(CMD1) + 1, 2 + len(CMD2) + 1)
    seq, nrows = session(log, out)
    size = (round(2 * PAD_X + cols * ADV), BAR + PAD_TOP + nrows * LINE + PAD_BOTTOM)
    rgb = [(draw(rows, cur, size), ms) for rows, cur, ms in seq]
    palette = rgb[-2][0].quantize(colors=128, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
    frames = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im, _ in rgb]
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=[ms for _, ms in rgb],
                   loop=0, disposal=1, optimize=False)
    return size, sum(ms for _, ms in rgb)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default="docs/assets/demo.gif")
    ap.add_argument("--capture-dir", help="read logs.txt and whyreach.txt from here instead of running the demo")
    a = ap.parse_args()
    if a.capture_dir:
        d = pathlib.Path(a.capture_dir)
        log = (d / "logs.txt").read_text().rstrip("\n")
        out = (d / "whyreach.txt").read_text().rstrip("\n").split("\n")
    else:
        log, out = capture()
    size, ms = render(log, out, a.out)
    print(f"{a.out}: {size[0]}x{size[1]}, {ms / 1000:.1f} s, {os.path.getsize(a.out) // 1024} KB")


if __name__ == "__main__":
    main()
