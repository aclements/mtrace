#!/usr/bin/python

import sqlite3
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
        self.dbFile = dbFile
        self.dataName = dataName
        self.accessId = accessId

        self.topId = None
        self.frames = None

    def __walk_call_stack(self, c, currentId):
        q = 'SELECT ret_id, end_pc FROM %s_call_intervals WHERE id = %lu'
        q = q % (self.dataName,
                 currentId)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('unexpected result')
        
        retId = rs[0][0]
        pc = rs[0][1]

        self.frames.append(MtraceCallInterval(pc))
                
        if retId != 0:
            self.__walk_call_stack(c, retId)

    def __build_frames(self):
        conn = sqlite3.connect(self.dbFile)
        c = conn.cursor()

        q = 'SELECT cpu, pc FROM %s_accesses WHERE access_id = %u'
        q = q % (self.dataName,
                 self.accessId)

        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('unexpected result')

        cpu = rs[0][0]
        pc = rs[0][1]
        
        self.frames = []
        self.frames.append(MtraceCallInterval(pc))

        q = 'SELECT id FROM %s_call_intervals WHERE cpu = %u AND ' + \
            'access_start < %lu AND %lu <= access_end'
        q = q % (self.dataName,
                 cpu,
                 self.accessId,
                 self.accessId)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('unexpected result')
        
        topId = rs[0][0]

        self.__walk_call_stack(c, topId)

        c.close()

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

def walk_call_stack(conn, dataName, topId):
    c = conn.cursor()

    print 'topId %lu'  % (topId)

    q = 'SELECT ret_id, end_pc FROM %s_call_intervals WHERE id = %lu'
    q = q % (dataName,
             topId)
    c.execute(q)
    rs = c.fetchall()
    if len(rs) != 1:
        raise Exception('unexpected result')

    retId = rs[0][0]
    startPc = rs[0][1]

    print 'startPc %lx' % ( uhex(startPc) )

    if retId == 0:
        print 'End'
    else:
        walk_call_stack(conn, dataName, retId)

    c.close()

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    accessId = int(argv[3])

    bt = MtraceBacktracer(dbFile, dataName, accessId)
    print bt.get_depth()

    for interval in bt:
        print interval

    print '------------'

    conn = sqlite3.connect(dbFile)
    c = conn.cursor()

    q = 'SELECT cpu, pc FROM %s_accesses WHERE access_id = %u'
    q = q % (dataName,
             accessId)

    c.execute(q)
    rs = c.fetchall()
    if len(rs) != 1:
        raise Exception('unexpected result')

    cpu = rs[0][0]
    pc = rs[0][1]

    print 'cpu %u pc %lx' % (cpu, uhex(pc))
    
    q = 'SELECT id FROM %s_call_intervals WHERE cpu = %u AND ' + \
        'access_start < %lu AND %lu <= access_end'
    q = q % (dataName,
             cpu,
             accessId,
             accessId)
    c.execute(q)
    rs = c.fetchall()
    if len(rs) != 1:
        raise Exception('unexpected result')

    topId = rs[0][0]
    print topId

    walk_call_stack(conn, dataName, topId);
    
    c.close()

if __name__ == "__main__":
    sys.exit(main())
