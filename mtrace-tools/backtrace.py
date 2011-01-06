#!/usr/bin/python

from mtracepy.mtrace import MtraceBacktracer
import sys

def usage():
    print """Usage: stack-trace.py DB-file name access-id
"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    accessId = int(argv[3])

    bt = MtraceBacktracer(dbFile, dataName, accessId)

    for interval in bt:
        print interval

if __name__ == "__main__":
    sys.exit(main())
