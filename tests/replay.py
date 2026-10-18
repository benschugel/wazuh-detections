#!/usr/bin/env python3
"""Replay recorded Wazuh alerts through wazuh-logtest and report rule changes.

Runs inside the test manager (tests/harness.sh), whose stock rules 60000 and
19000 are patched to accept JSON, so Windows and SCA events can be
re-evaluated. Takes alerts.json files copied from a live manager; those hold
real host data and must not be committed.

Usage: replay.py <label> <alerts file> [<alerts file> ...]
"""
import collections
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logtest  # noqa: E402

label, files = sys.argv[1], sys.argv[2:]

token = None
trans = collections.Counter()
before = collections.Counter()
after = collections.Counter()
paged_before = collections.Counter()
paged_after = collections.Counter()
warned = False
for f in files:
    day = f.split("/")[-1]
    op = gzip.open if f.endswith(".gz") else open
    with op(f, "rt", errors="replace") as fh:
        for line in fh:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            d = a.get("data", {})
            if "win" in d:
                ev = {"win": d["win"]}
            elif "sca" in d:
                ev = {"sca": d["sca"]}
            else:
                continue
            old = (a["rule"]["id"], a["rule"]["level"])
            r = logtest.ask(ev, "replay", token, origin="replay")
            token = r["token"]
            if not warned and r["messages"]:
                bad = [m for m in r["messages"] if m.startswith(("WARNING", "ERROR"))]
                if bad:
                    print("LOGTEST MESSAGES:", bad[:5])
                    warned = True
            new = (r["id"], r["level"])
            trans[(old, new)] += 1
            before[day] += 1
            paged_before[day] += old[1] >= 10
            if new[1] > 0:
                after[day] += 1
                paged_after[day] += new[1] >= 10

print("=== %s ===" % label)
for day in before:
    print("%-28s alerts %5d -> %5d   level>=10 %4d -> %4d"
          % (day, before[day], after[day], paged_before[day], paged_after[day]))
print("--- changed outcomes (recorded -> replayed) ---")
for (old, new), n in sorted(trans.items(), key=lambda kv: -kv[1]):
    if old != new:
        print("%6d  %s L%s -> %s L%s" % (n, old[0], old[1], new[0], new[1]))
same = sum(n for (o, nw), n in trans.items() if o == nw)
print("unchanged: %d of %d" % (same, sum(trans.values())))
