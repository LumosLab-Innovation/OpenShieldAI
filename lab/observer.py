"""Separate observation path, inaccessible through the public proxy."""
import json
import sys
import urllib.request

PATHS = {'state': '/_lab/state'}
if len(sys.argv) != 2 or sys.argv[1] not in PATHS:
    raise SystemExit('unknown fixed observer operation')
with urllib.request.urlopen('http://app:8000' + PATHS[sys.argv[1]], timeout=5) as response:
    print(json.dumps(json.load(response)))
