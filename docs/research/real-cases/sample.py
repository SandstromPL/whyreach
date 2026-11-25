#!/usr/bin/env python3
"""Fetch the real-case pools and shuffle them (docs/research/real-cases.md).

For each source, the union of its fixed queries' results, without
duplicates, sorted by ID, then shuffled with the fixed seed. Writes
pool-<source>.json next to this file: the queries, the fetch date and the
cases in the order they are looked at. Standard library only; GitHub goes
through `gh api`, signed in as the owner.

    python3 docs/research/real-cases/sample.py
"""

import gzip
import json
import random
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SEED = 20261125
FROM = datetime(2021, 1, 1, tzinfo=timezone.utc)
UNTIL = datetime(2026, 11, 25, tzinfo=timezone.utc)
HERE = Path(__file__).resolve().parent
UA = "whyreach-real-cases (research script)"

SO_QUERIES = [
    {"tagged": "docker-compose", "title": "connect"},
    {"tagged": "docker-compose", "title": "refused"},
    {"tagged": "docker-compose", "title": "resolve"},
    {"tagged": "docker-compose", "title": "reach"},
    {"tagged": "docker", "title": "connection refused"},
    {"tagged": "docker-compose", "q": "services ECONNREFUSED"},
]
FORUM_QUERIES = ['"connection refused"', '"could not resolve"', '"can\'t connect"', '"timed out"']
GITHUB_QUERIES = [
    '"docker compose" "connection refused" is:issue is:closed created:>2023-01-01',
    '"docker-compose.yml" "ECONNREFUSED" is:issue is:closed created:>2023-01-01',
]


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
            return json.loads(body)
        except OSError:
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))


def stackoverflow():
    seen = {}
    for q in SO_QUERIES:
        page = 1
        while True:
            params = dict(q, site="stackoverflow", accepted="True", pagesize=100, page=page,
                          fromdate=int(FROM.timestamp()), todate=int(UNTIL.timestamp()),
                          sort="creation", order="asc")
            d = get_json("https://api.stackexchange.com/2.3/search/advanced?" + urllib.parse.urlencode(params))
            for it in d.get("items", []):
                seen[it["question_id"]] = {
                    "id": f"so-{it['question_id']}",
                    "title": it["title"],
                    "url": f"https://stackoverflow.com/questions/{it['question_id']}",
                    "created": datetime.fromtimestamp(it["creation_date"], timezone.utc).date().isoformat(),
                }
            time.sleep(max(1, d.get("backoff", 0)))
            if not d.get("has_more"):
                break
            page += 1
    return [seen[k] for k in sorted(seen)]


def forum():
    seen = {}
    for q in FORUM_QUERIES:
        page = 1
        while True:
            term = f"{q} status:solved after:{FROM.date().isoformat()} before:{UNTIL.date().isoformat()}"
            d = get_json("https://forums.docker.com/search.json?" + urllib.parse.urlencode({"q": term, "page": page}))
            topics = d.get("topics", [])
            for t in topics:
                seen[t["id"]] = {
                    "id": f"forum-{t['id']}",
                    "title": t["title"],
                    "url": f"https://forums.docker.com/t/{t['id']}",
                    "created": t["created_at"][:10],
                }
            time.sleep(1)
            if not topics or not d.get("grouped_search_result", {}).get("more_full_page_results"):
                break
            page += 1
    return [seen[k] for k in sorted(seen)]


def github():
    seen = {}
    for q in GITHUB_QUERIES:
        # The search API returns at most 1,000 results a query: the pool is
        # the first 1,000 by GitHub's own ranking.
        for page in range(1, 11):
            out = subprocess.run(["gh", "api", "-X", "GET", "search/issues", "-f", f"q={q}",
                                  "-f", "per_page=100", "-f", f"page={page}"],
                                 check=True, capture_output=True, text=True).stdout
            items = json.loads(out).get("items", [])
            for it in items:
                repo = it["repository_url"].removeprefix("https://api.github.com/repos/")
                seen[it["id"]] = {
                    "id": f"gh-{repo.replace('/', '-')}-{it['number']}",
                    "title": it["title"],
                    "url": it["html_url"],
                    "created": it["created_at"][:10],
                }
            time.sleep(2.5)
            if len(items) < 100:
                break
    return [seen[k] for k in sorted(seen)]


def main():
    fetched = datetime.now(timezone.utc).date().isoformat()
    for name, fetch, queries in [("stackoverflow", stackoverflow, SO_QUERIES),
                                 ("forum", forum, FORUM_QUERIES),
                                 ("github", github, GITHUB_QUERIES)]:
        pool = fetch()
        random.Random(SEED).shuffle(pool)
        out = {"source": name, "fetched": fetched, "seed": SEED, "queries": queries,
               "size": len(pool), "order": pool}
        (HERE / f"pool-{name}.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
        print(name, len(pool))


if __name__ == "__main__":
    main()
