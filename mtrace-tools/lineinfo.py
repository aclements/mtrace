#!/usr/bin/python

from  mtracepy.columns import ColumnValue, Address, Unsigned, AccessType, LabelString, create_column_string, create_column_objects, get_column_object

import sqlite3
import sys

mtrace_label_heap       = 1
mtrace_label_block      = 2
mtrace_label_static     = 3
mtrace_label_percpu     = 4

mtrace_label_str        =  { mtrace_label_heap   : 'heap',
                             mtrace_label_block  : 'block',
                             mtrace_label_static : 'static',
                             mtrace_label_percpu : 'percpu' }

def hex2sint(val):
    l = long(val, 16)
    if l > sys.maxint:
        l = l - 2L*sys.maxint - 2
    return l

def slong(l):
    if l > sys.maxint:
        l = l - 2L*sys.maxint - 2
    return l

def usage():
    print """Usage: lineinfo.py DB-file name address
"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    hexAddress = argv[3]

    startAddress = long(hexAddress, 16) & ~63
    endAddress = startAddress + 64

    print 'cache line %s' % hex(startAddress)[:-1]

    startAddress = slong(startAddress)
    endAddress = slong(endAddress)

    conn = sqlite3.connect(dbFile)

    columns = [ 
                ColumnValue(LabelString.create, 'str'),
                ColumnValue(Unsigned.create, 'label_id'),
                ColumnValue(Address.create, 'guest_addr'),
                ColumnValue(Address.create, 'guest_addr_end'),
                ColumnValue(Unsigned.create, 'access_start'),
                ColumnValue(Unsigned.create, 'access_end'),
              ]

    select = create_column_string(columns)

    print '  %-16s  %10s  %16s  %16s  %16s  %16s  %16s' % ('str', 'type', 'label_id', 'guest_addr', 'guest_addr_end', 'access_start', 'access_end')
    print '  %-16s  %10s  %16s  %16s  %16s  %16s  %16s' % ('---', '----', '--------', '----------', '--------------', '------------', '----------')

    for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
        if labelType == mtrace_label_block:
            continue

        q = 'SELECT ' + select + ' FROM %s_labels%u WHERE (%ld <= guest_addr AND guest_addr < %ld) OR ' + \
            '(%ld <= guest_addr_end AND guest_addr_end < %ld) OR (%ld > guest_addr AND guest_addr_end > %ld)'
        q = q % (dataName,
                 labelType,
                 startAddress,
                 endAddress,
                 startAddress,
                 endAddress,
                 startAddress,
                 endAddress)

        c = conn.cursor()
        c.execute(q)            

        for row in c:
            values = create_column_objects(columns, row)
            s = '  %-16s' % values[0]
            s += '  %10s' % mtrace_label_str[labelType]

            for value in values[1:]:
                s += '  %16s' % value.__str__()

            print s

        c.close()

if __name__ == "__main__":
    sys.exit(main())

