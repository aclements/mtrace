#!/usr/bin/python

import sqlite3
import sys

def usage():
    print """Usage: tidinfo.py DB-file name TID [TID TID ...]
"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        usage()

    dbFile = argv[1]
    dataName = argv[2]

    conn = sqlite3.connect(dbFile)
    c = conn.cursor()
    tmpl = 'SELECT str FROM %s_tasks WHERE tid = %s'

    for tid in argv[3:]:
        q = tmpl % (dataName, tid)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        if len(rs) == 0:
            print '%-16s %s' % (tid, '(unknown)')
        else:
            print '%-16s %s' % (tid, rs[0][0])

if __name__ == "__main__":
    sys.exit(main())
