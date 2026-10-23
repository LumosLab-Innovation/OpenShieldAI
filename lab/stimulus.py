"""Privileged synthetic experiment setup; never an observer/Shield tool."""
import json
import sys
import urllib.request

PATHS = {name: '/_lab/' + name for name in ('checkpoint', 'contaminate', 'clean-fixture', 'data-loss', 'reset-data', 'inconsistent')}
if len(sys.argv) != 2 or sys.argv[1] not in PATHS:
    raise SystemExit('unknown fixed experiment operation')
with urllib.request.urlopen('http://app:8000' + PATHS[sys.argv[1]], timeout=5) as response:
    print(json.dumps(json.load(response)))
