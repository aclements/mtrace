#!/usr/bin/python

import sys
import mtracepy.summary

def usage():
    print """Usage: %s DB-file name""",
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) != 3:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    print mtracepy.summary.MtraceSummary(dbFile, dataName)

if __name__ == "__main__":
    sys.exit(main())
