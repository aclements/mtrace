#!/usr/bin/python

import mtracepy.lock
import sys

def usage():
    print """Usage: serialsum.py DB-file name
"""
    exit(1)

def print_all(detail):
    print '  %-16s  %16s  %16s  %16s  %16s' % ('id', 'pc', 'addr', 'cpu', 'access type')
    print '  %-16s  %16s  %16s  %16s  %16s' % ('--', '--', '----', '---', '-----------')
    for access in detail:
        print '  %-16s  %16s  %16s  %16s  %16s' % (access.get_value('access_id'), 
                                                   access.get_value('pc'),
                                                   access.get_value('guest_addr'),
                                                   access.get_value('cpu'),
                                                   access.get_value('access_type'))

def print_unique_pc(detail):
    d = {}
    for access in detail:
        key = access.get_value('pc').__str__()
        if key in d:
            value = d[key]
            d[key] = [ value[0] + 1, value[1] ]
        else:
            d[key] = [ 1, access.get_value('access_id').__str__() ]

    l = sorted(d.items(), key=lambda k: k[1][0], reverse=True)

    print '  %-8s  %16s  %16s' % ('count', 'pc', '(sample) id' )
    print '  %-8s  %16s  %16s' % ('-----', '--', '-----------')
    for i in l:
        print '  %-8u  %16s  %16s' % ( i[1][0], i[0], i[1][1] )

print_types = {
    'all'       : print_all,
    'unique-pc' : print_unique_pc
}
default_print_fn = print_all

def parse_args(argv):
    args = argv[4:]

    def print_handler(val):
        global default_print_fn
        default_print_fn = print_types[val]

    handler = {
        '-print'      : print_handler,
    }

    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage()

    dbFile = argv[1]
    dataName = argv[2]

    locks = mtracepy.lock.get_locks(dbFile, dataName)
    locks = sorted(locks, key=lambda l: l.get_hold_time(), reverse=True)
    for l in locks:
        print l

if __name__ == "__main__":
    sys.exit(main())
