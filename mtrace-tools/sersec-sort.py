#!/usr/bin/python

import sys
import json

serials = json.loads(sys.stdin.read())["serial-sections"]
serials = sorted(serials, key=lambda sec: sec["total-cycles"], reverse=True)
for s in serials:
    s["per-acquire-pc"] = sorted(s["per-acquire-pc"], key=lambda sec: sec["total-cycles"], reverse=True)
    s["coherence-miss-list"] = sorted(s["coherence-miss-list"], key=lambda sec: sec["count"], reverse=True)
    for p in s["per-acquire-pc"]:
        p["coherence-miss-list"] = sorted(p["coherence-miss-list"], key=lambda sec: sec["count"], reverse=True)
print json.dumps(serials, indent=4)
