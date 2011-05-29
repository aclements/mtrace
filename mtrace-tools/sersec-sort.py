#!/usr/bin/python

import sys
import json

serials = json.loads(sys.stdin.read())["serial-sections"]
serials = sorted(serials, key=lambda sec: sec["cycles"], reverse=True)
for s in serials:
    s["per-acquire-pc"] = sorted(s["per-acquire-pc"], key=lambda sec: sec["cycles"], reverse=True)
print json.dumps(serials, indent=4)
