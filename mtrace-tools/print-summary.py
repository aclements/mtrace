#!/usr/bin/python

import sys
import mtracepy.model

def usage(argv):
    print """Usage: %s DB-file name""" % (argv[0]),
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) != 3:
        usage(argv)

    dbFile = argv[1]
    dataName = argv[2]
    print mtracepy.model.MtraceSummary(dbFile, dataName)

if __name__ == "__main__":
    sys.exit(main())
