#!/usr/bin/python

from mtracepy.mtrace import MtraceInstanceDetail
import mtracepy.util
import sqlite3
import sys

def usage():
    print 'usage: poo.py DB-file data-name syscall-name label-name label-type'
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

def get_miss_count(conn, dataName, syscallName, labelId):
    '''Returns how many unique cache lines form labelId 
    syscall named syscallName misses on'''

    q = '''SELECT DISTINCT call_trace_tag, guest_addr from %s_accesses WHERE label_id = %lu
AND EXISTS (SELECT * FROM %s_call_traces WHERE
     %s_call_traces.cpu = %s_accesses.cpu
     AND %s_call_traces.call_trace_tag = %s_accesses.call_trace_tag
     AND %s_call_traces.name = "%s")
'''
    q = q % (dataName, labelId,
             dataName, 
             dataName, dataName,
             dataName, dataName,
             dataName, syscallName)
    c = conn.cursor()
    c.execute(q)

    tagDict = {}
    for row in c:
        tag = row['call_trace_tag']
        guestAddr = row['guest_addr']
        if tag in tagDict:
            tagDict[tag] = tagDict[tag] + 1
        else:
            tagDict[tag] = 1

    total = 0
    vals = tagDict.values()
    for count in vals:
        total += count

    return float(total)
    
def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 6:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    syscallName = argv[3]
    labelName = argv[4]
    labelType = int(argv[5])

    conn = sqlite3.connect(dbFile)
    conn.row_factory = sqlite3.Row
    q = 'SELECT DISTINCT label_id FROM %s_labels%u WHERE str = \"%s\"'
    q = q % (dataName, labelType, labelName)
    c = conn.cursor()
    c.execute(q)

    total = 0
    for row in c:
        labelId = row['label_id']
        total += get_miss_count(conn, dataName, syscallName, labelId)
    print total
        
if __name__ == "__main__":
    sys.exit(main())
