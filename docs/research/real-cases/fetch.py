#!/usr/bin/env python3
"""Fetch what the labeler and the reproducer read (docs/research/real-cases.md).

For the first N cases of each pool, in the shuffled order, writes to
bin/realcases/raw/<case>/ (outside git: it's other people's text):
  question.md  the question alone, for the reproducer;
  thread.md    the question with its answers and comments, for the labeler;
  meta.json    the link, the author and the date, for attribution.
Standard library only; GitHub goes through `gh api`.

    python3 docs/research/real-cases/fetch.py stackoverflow=45 forum=33 github=50
"""

import gzip
import html
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE.parents[2] / "bin" / "realcases" / "raw"
UA = "whyreach-real-cases (research script)"


def get(url, raw=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
            return body.decode() if raw else json.loads(body)
        except OSError:
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))


def write(case, question, thread, meta):
    d = RAW / case
    d.mkdir(parents=True, exist_ok=True)
    (d / "question.md").write_text(question)
    (d / "thread.md").write_text(thread)
    (d / "meta.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")


def day(ts):
    return datetime.fromtimestamp(ts, timezone.utc).date().isoformat()


def stackoverflow(cases):
    f = get("https://api.stackexchange.com/2.3/filters/create?" + urllib.parse.urlencode({
        "include": "question.body_markdown;question.comments;question.answers;answer.body_markdown;"
                   "answer.comments;comment.body_markdown;answer.is_accepted",
        "base": "default", "unsafe": "false"}))["items"][0]["filter"]
    ids = [c["id"].removeprefix("so-") for c in cases]
    items = {}
    for i in range(0, len(ids), 100):
        d = get(f"https://api.stackexchange.com/2.3/questions/{';'.join(ids[i:i + 100])}?"
                + urllib.parse.urlencode({"site": "stackoverflow", "filter": f, "pagesize": 100}))
        items |= {str(q["question_id"]): q for q in d["items"]}
        time.sleep(max(1, d.get("backoff", 0)))
    un = html.unescape
    for c in cases:
        q = items.get(c["id"].removeprefix("so-"))
        if q is None:
            print("missing", c["id"], file=sys.stderr)
            continue
        who = un(q.get("owner", {}).get("display_name", "?"))
        question = f"# {un(q['title'])}\n\nAsked on Stack Overflow by {who}, {day(q['creation_date'])}.\n\n{un(q.get('body_markdown', ''))}\n"
        t = [question]
        for cm in q.get("comments", []):
            t.append(f"> Comment on the question ({un(cm.get('owner', {}).get('display_name', '?'))}): {un(cm.get('body_markdown', ''))}\n")
        for a in sorted(q.get("answers", []), key=lambda a: (not a.get("is_accepted"), -a.get("score", 0))):
            mark = "ACCEPTED ANSWER" if a.get("is_accepted") else "Answer"
            t.append(f"\n---\n\n## {mark} by {un(a.get('owner', {}).get('display_name', '?'))} (score {a.get('score', 0)}), {day(a['creation_date'])}\n\n{un(a.get('body_markdown', ''))}\n")
            for cm in a.get("comments", []):
                t.append(f"> Comment ({un(cm.get('owner', {}).get('display_name', '?'))}): {un(cm.get('body_markdown', ''))}\n")
        write(c["id"], question, "\n".join(t), {"url": c["url"], "author": who, "created": day(q["creation_date"]),
                                                "licence": "CC BY-SA 4.0 (Stack Overflow)"})


def forum(cases):
    for c in cases:
        tid = c["id"].removeprefix("forum-")
        t = get(f"https://forums.docker.com/t/{tid}.json")
        time.sleep(1)
        raw = get(f"https://forums.docker.com/raw/{tid}", raw=True)
        time.sleep(1)
        posts = [p.strip() for p in raw.split("\n-------------------------\n")]
        first = t["post_stream"]["posts"][0]
        accepted = (t.get("accepted_answer") or {}).get("post_number")
        question = f"# {t['title']}\n\nAsked on the Docker Community Forums by {first['username']}, {t['created_at'][:10]}.\n\n{posts[0]}\n"
        thread = [question]
        for n, p in enumerate(posts[1:], start=2):
            mark = "SOLUTION (marked by the asker)" if n == accepted else "Reply"
            thread.append(f"\n---\n\n## {mark}, post #{n}\n\n{p}\n")
        write(c["id"], question, "\n".join(thread), {"url": c["url"], "author": first["username"],
                                                     "created": t["created_at"][:10], "accepted_post": accepted})


def gh(path):
    out = subprocess.run(["gh", "api", "--paginate", path], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if not out.startswith("[") else json.loads(out.replace("][", ","))


def github(cases):
    for c in cases:
        owner, repo, _, num = c["url"].removeprefix("https://github.com/").split("/")[:4]
        i = gh(f"repos/{owner}/{repo}/issues/{num}")
        comments = gh(f"repos/{owner}/{repo}/issues/{num}/comments")
        time.sleep(1)
        question = f"# {i['title']}\n\nIssue opened in {owner}/{repo} by {i['user']['login']}, {i['created_at'][:10]}.\n\n{i.get('body') or ''}\n"
        thread = [question]
        for cm in comments:
            thread.append(f"\n---\n\n## Comment by {cm['user']['login']} ({cm.get('author_association', '')}), {cm['created_at'][:10]}\n\n{cm.get('body') or ''}\n")
        thread.append(f"\n---\n\nClosed {(i.get('closed_at') or '')[:10]}, reason: {i.get('state_reason')}.\n")
        write(c["id"], question, "\n".join(thread), {"url": c["url"], "author": i["user"]["login"],
                                                     "created": i["created_at"][:10], "state_reason": i.get("state_reason")})


def main():
    want = dict(a.split("=") for a in sys.argv[1:])
    for name, fn in [("stackoverflow", stackoverflow), ("forum", forum), ("github", github)]:
        if name in want:
            pool = json.loads((HERE / f"pool-{name}.json").read_text())["order"][: int(want[name])]
            fn(pool)
            print(name, len(pool))


if __name__ == "__main__":
    main()
