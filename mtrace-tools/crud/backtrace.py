#!/usr/bin/python

from mtracepy.mtrace import MtraceBacktracer
from mtracepy.addr2line import Addr2Line
import sys

default_exefile = None

def usage():
    print """Usage: backtrace.py DB-file name access-id [ -exefile exfile ]

    'exfile' is the executable for which addresses should be translated.

"""
    exit(1)

def parse_args(argv):
    args = argv[4:]

    def exefile_handler(val):
        global default_exefile
        default_exefile = val

    handler = {
        '-exefile'      : exefile_handler,
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
    accessId = int(argv[3])

    addr2Line = None
    if default_exefile != None:
        addr2Line = Addr2Line(default_exefile)

    bt = MtraceBacktracer(dbFile, dataName, accessId)

    if addr2Line == None:
        for interval in bt:
            print interval
    else:
        for interval in bt:
            addr = interval.__str__()
            s = '  %-16s  %-64s  %s' % (addr, 
                                        addr2Line.file(addr) + ':' + addr2Line.line(addr),
                                        addr2Line.func(addr))
            print s
        

if __name__ == "__main__":
    sys.exit(main())
