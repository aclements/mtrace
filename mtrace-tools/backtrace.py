#!/usr/bin/python

import mtrace
import sys

# XXX there must be a better way..
def uhex(i):
    return (i & 0xffffffffffffffff)

def usage():
    print """Usage: stack-trace.py DB-file name access-id
"""
    exit(1)

class MtraceCallInterval:
    def __init__(self, pc):
        self.pc = pc

    def __str__(self):
        return '%lx' % uhex(self.pc)

class MtraceBacktracer:
    def __init__(self, dbFile, dataName, accessId):
        self.mtraceDB = mtrace.MtraceDB(dbFile)
        self.dataName = dataName
        self.accessId = accessId

        self.topId = None
        self.frames = None

    def __walk_call_stack(self, currentId):
        q = 'SELECT ret_id, end_pc FROM %s_call_intervals WHERE id = %lu'
        q = q % (self.dataName,
                 currentId)

        r = self.mtraceDB.exec_single(q)

        retId = r[0]
        pc = r[1]

        self.frames.append(MtraceCallInterval(pc))

        if retId != 0:
            self.__walk_call_stack(retId)

    def __build_frames(self):
        q = 'SELECT cpu, pc FROM %s_accesses WHERE access_id = %u'
        q = q % (self.dataName,
                 self.accessId)

        r = self.mtraceDB.exec_single(q)
        cpu = r[0]
        pc = r[1]
        
        self.frames = []
        self.frames.append(MtraceCallInterval(pc))

        q = 'SELECT id FROM %s_call_intervals WHERE cpu = %u AND ' + \
            'access_start < %lu AND %lu <= access_end'
        q = q % (self.dataName,
                 cpu,
                 self.accessId,
                 self.accessId)

        topId = self.mtraceDB.exec_single(q)[0]
        self.__walk_call_stack(topId)

    def get_depth(self):
        if self.frames == None:
            self.__build_frames()

        return len(self.frames)

    def get_interval(self, i):
        if self.frames == None:
            self.__build_frames()

        return self.frames[i]

    class Iter:
        def __init__(self, bt):
            self.i = 0
            self.bt = bt

        def __iter__(self):
            return self

        def next(self):
            if self.bt.get_depth() == self.i:
                raise StopIteration();
            interval = self.bt.get_interval(self.i)
            self.i += 1
            return interval

    def __iter__(self):
        return MtraceBacktracer.Iter(self)

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
