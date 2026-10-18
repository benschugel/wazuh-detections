#!/usr/bin/env python3
"""Run the rule test cases in tests/cases through wazuh-logtest.

Runs inside a manager container that has the repository's decoders and rules
loaded and the two stock-rule harness patches applied (see tests/harness.sh).

    run_cases.py                 run every case file
    run_cases.py 100500 100241   run only these rule ids
    run_cases.py --list          list case files and counts

Case files are JSON, one per rule id:

    {"rule": "100250", "title": "...", "cases": [
      {"name": "...", "location": "guard", "event": {...} or "raw line",
       "expect": {"id": "100250", "level": 3}},          level is optional
      {"name": "...", "event": ..., "info": true},        printed, never fails
      {"name": "...", "events": [...], "expect_ids": [...],
       "summary": {"rule": "100500", "must_contain": "...", "must_not_contain": "..."}}
    ]}

A case with "events" is a sequence: every event is sent in the same logtest
session (token) with a one second gap, because analysisd counts frequency
only across different seconds, and the rule id of each event must match
"expect_ids" in order. "summary" checks the description of the first event
that hit the given rule.
"""
import argparse
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logtest  # noqa: E402

DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def load(selectors, cases_dir):
    paths = []
    if not selectors:
        paths = sorted(glob.glob(os.path.join(cases_dir, "*.json")))
    for sel in selectors:
        if os.path.isfile(sel):
            paths.append(sel)
        else:
            p = os.path.join(cases_dir, sel + ".json")
            if not os.path.isfile(p):
                sys.exit("no case file for %r (looked for %s)" % (sel, p))
            paths.append(p)
    files = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            files.append(json.load(fh))
    return files


class Runner:
    def __init__(self, sock, gap):
        self.sock = sock
        self.gap = gap
        self.failed = 0
        self.total = 0
        self.warned = False

    def ask(self, event, location, token=None):
        r = logtest.ask(event, location, token, sock=self.sock)
        if not self.warned and r["messages"]:
            bad = [m for m in r["messages"] if m.startswith(("WARNING", "ERROR"))]
            if bad:
                print("LOGTEST MESSAGES:", bad[:5])
                self.warned = True
        return r

    def single(self, rule, case):
        r = self.ask(case["event"], case.get("location", "guard"))
        got = "%s L%s" % (r["id"], r["level"])
        if case.get("info"):
            print("info %-7s %-70s -> %s" % (rule, case["name"], got))
            return
        exp = case["expect"]
        ok = r["id"] == exp["id"] and ("level" not in exp or r["level"] == exp["level"])
        want = exp["id"] + (" L%s" % exp["level"] if "level" in exp else "")
        self.report(rule, case["name"], ok, got, want)

    def sequence(self, rule, case):
        token, got, summary_desc = None, [], None
        summary = case.get("summary")
        for ev in case["events"]:
            r = self.ask(ev, case.get("location", "guard"), token)
            token = r["token"]
            got.append(r["id"])
            if summary and summary_desc is None and r["id"] == summary["rule"]:
                summary_desc = r["description"]
            time.sleep(self.gap)
        ok = got == case["expect_ids"]
        self.report(rule, case["name"], ok, " ".join(got), " ".join(case["expect_ids"]))
        if summary:
            desc = summary_desc or ""
            s_ok = True
            if "must_contain" in summary and summary["must_contain"] not in desc:
                s_ok = False
            if "must_not_contain" in summary and summary["must_not_contain"] in desc:
                s_ok = False
            self.report(rule, case["name"] + " (summary description)", s_ok, repr(desc),
                        "contains %r" % summary.get("must_contain", ""))

    def report(self, rule, name, ok, got, want):
        self.total += 1
        self.failed += not ok
        line = "%s %-7s %-70s -> %s" % ("PASS" if ok else "FAIL", rule, name, got)
        if not ok:
            line += "   (wanted %s)" % want
        print(line)

    def run_file(self, doc):
        rule = doc["rule"]
        print("== %s: %s" % (rule, doc.get("title", "")))
        for case in doc["cases"]:
            if "events" in case:
                self.sequence(rule, case)
            else:
                self.single(rule, case)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rules", nargs="*", help="rule ids or case file paths (default: all)")
    ap.add_argument("--cases-dir", default=DEFAULT_DIR)
    ap.add_argument("--sock", default=logtest.SOCK)
    ap.add_argument("--gap", type=float, default=1.05, help="seconds between events of a sequence")
    ap.add_argument("--list", action="store_true", help="list case files and exit")
    args = ap.parse_args()

    files = load(args.rules, args.cases_dir)
    if args.list:
        for doc in files:
            print("%-7s %3d cases  %s" % (doc["rule"], len(doc["cases"]), doc.get("title", "")))
        print("%d files, %d cases" % (len(files), sum(len(d["cases"]) for d in files)))
        return 0

    runner = Runner(args.sock, args.gap)
    for doc in files:
        runner.run_file(doc)
    print("\n%d checks, %d failed" % (runner.total, runner.failed))
    return 1 if runner.failed else 0


if __name__ == "__main__":
    sys.exit(main())
