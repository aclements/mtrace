#!/usr/bin/python

import mtracepy.lock
import sys

def usage():
    print """Usage: serialsum.py DB-file name
"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage()

    dbFile = argv[1]
    dataName = argv[2]

    locks = mtracepy.lock.get_locks(dbFile, dataName)
    locks = sorted(locks, key=lambda l: l.get_exclusive_hold_time(), reverse=True)
    for l in locks:
        print l
        tids = l.get_tids()
        for tid in tids.keys():
            time = tids[tid]
            print '  %lu:%lu' % (tid, (time * 100) / l.get_exclusive_hold_time())

if __name__ == "__main__":
    sys.exit(main())
