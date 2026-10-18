#!/usr/bin/env python3
"""Check that every decoder, rule and Sysmon XML file is well-formed.

Wazuh rule and decoder files are XML fragments with several top-level
elements, so each one is parsed inside a wrapper root. Exit code 1 if any
file fails. Runs with the standard library only.
"""
import glob
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATTERNS = ["decoders/*.xml", "detections/*.xml", "tuning/*.xml", "sysmon/*.xml"]

failed = 0
files = sorted(p for pat in PATTERNS for p in glob.glob(os.path.join(ROOT, pat)))
for path in files:
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    try:
        with open(path, encoding="utf-8") as fh:
            ET.fromstring("<wazuh-detections>" + fh.read() + "</wazuh-detections>")
        print("ok    ", rel)
    except (ET.ParseError, UnicodeDecodeError) as e:
        failed += 1
        print("FAIL  ", rel, "-", e)
print("%d files, %d failed" % (len(files), failed))
sys.exit(1 if failed or not files else 0)
