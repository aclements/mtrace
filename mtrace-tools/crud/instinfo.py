#!/usr/bin/python

from mtracepy.mtrace import MtraceInstanceDetail
import sys

def usage():
    print """Usage: instinfo.py DB-file name label-id [ -print printtype ]

    'printtype' is the method used to print results. Valid values are:
      'all'        -- all accesses
      'unique-pc'  -- only one accesses per unique PC
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
    if len(argv) < 4:
        usage()

    parse_args(argv)

    dbFile = argv[1]
    dataName = argv[2]
    labelId = int(argv[3])

    detail = MtraceInstanceDetail(dbFile, dataName, None, labelId)

    default_print_fn(detail)

if __name__ == "__main__":
    sys.exit(main())
