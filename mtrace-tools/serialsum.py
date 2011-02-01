#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex
import sqlite3
import sys

DEFAULT_FILTERS         = []
DEFAULT_COLS            = ['pc', 'length', 'percent']
PRINT_COLS              = []
SUMMARY                 = None

class FilterLabel:
    def __init__(self, labelName):
        self.labelName = labelName

    def filter(self, summaryObject):
        return self.labelName != summaryObject.name

class FilterTidCount:
    def __init__(self, count):
        self.count = count

    def filter(self, lock):
        return len(lock.get_tids()) > self.count

class FilterCpuCount:
    def __init__(self, count):
        self.count = count

    def filter(self, lock):
        return len(lock.get_cpus()) > self.count

def apply_filters(lst, filters):
    if len(filters) > 0:
        lst2 = []
        for e in lst:
            lst2.append(e)
            for f in filters:
                if f.filter(e) == False:
                    lst2.pop()
                    break
        return lst2
    else:
        return lst

def usage():
    print """Usage: serialsum.py DB-file name [ -filter-label filter-label 
    -filter-tid-count filter-tid-count -filter-cpu-count filter-cpu-count 
    -print col ]

    'filter-tid-count' is the number of TIDs minus one that must execute
      a serial section

    'filter-cpu-count' is the number of CPUs minus one that must execute
      a serial section

    'col' is the name of a column.  Valid values are:
      'pc'      --
      'length'  --
      'percent' --
      'cpus'    --
      'tids'    --
"""
    exit(1)

def parse_args(argv):
    args = argv[3:]

    def filter_label_handler(label):
        global DEFAULT_FILTERS
        DEFAULT_FILTERS.append(FilterLabel(label))

    def filter_tid_count_handler(count):
        global DEFAULT_FILTERS
        DEFAULT_FILTERS.append(FilterTidCount(int(count)))

    def filter_cpu_count_handler(count):
        global DEFAULT_FILTERS
        DEFAULT_FILTERS.append(FilterCpuCount(int(count)))

    def print_handler(col):
        global PRINT_COLS
        PRINT_COLS.append(col)

    handler = {
        '-filter-label'  : filter_label_handler,
        '-filter-tid-count' : filter_tid_count_handler,
        '-filter-cpu-count' : filter_cpu_count_handler,
        '-print' : print_handler
    }

    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])

    global PRINT_COLS
    if len(PRINT_COLS) == 0:
        PRINT_COLS = DEFAULT_COLS

def get_col_value(lock, col):
    def get_pc():
        '''Return the PC of the most costly section'''
        pcs = lock.get_pcs()
        pc = sorted(pcs.keys(), key=lambda k: pcs[k], reverse=True)[0]
        return '%016lx' % uhex(pc)
       
    def get_length():
        return str(lock.get_exclusive_hold_time())

    def get_percent():
        return '%.2f' % ((lock.get_exclusive_hold_time() * 100.0) / SUMMARY.work)

    def get_cpus():
        cpuTable = lock.get_cpus()
        cpus = cpuTable.keys()
        time = cpuTable[cpus[0]]
        cpuString = '%u:%.2f%%' % (cpus[0], (time * 100.0) / lock.get_exclusive_hold_time())
        for cpu in cpus[1:]:
            time = cpuTable[cpu]
            cpuString += ' %u:%.2f%%' % (cpu, (time * 100.0) / lock.get_exclusive_hold_time())
        return cpuString

    def get_tids():
        tids = lock.get_tids()
        tidsPercent = ''
        totPercent = (lock.get_exclusive_hold_time() * 100.0) / float(SUMMARY.work)
        for tid in tids.keys():
            time = tids[tid]
            tidsPercent += '%lu:%.2f%% ' % (tid, (time * 100.0) / lock.get_exclusive_hold_time())
        return tidsPercent

    colValueFuncs = {
        'pc' : get_pc,
        'length' : get_length,
        'percent' : get_percent,
        'cpus' : get_cpus,
        'tids' : get_tids
    }
    
    return colValueFuncs[col]()
    

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage()

    dbFile = argv[1]
    dataName = argv[2]
    parse_args(argv)

    global SUMMARY
    SUMMARY = mtracepy.summary.MtraceSummary(dbFile, dataName)
    duration = SUMMARY.work
    
    tidSet = {}

    locks = mtracepy.lock.get_locks(dbFile, dataName)
    locks.extend(mtracepy.harcrit.get_harcrits(dbFile, dataName));

    locks = sorted(locks, key=lambda l: l.get_exclusive_hold_time(), reverse=True)
    locks = apply_filters(locks, DEFAULT_FILTERS)

    headerStr = '%-20s  %16s  %16s' % ('name', 'id', 'lock')
    borderStr = '%-20s  %16s  %16s' % ('----', '--', '----')
    for col in PRINT_COLS:
        headerStr += '  %16s' % col
        borderStr += '  %16s' % '----'
#    print '%-20s  %16s  %16s' % ('name', 'id', 'lock')
#    print '%-20s  %16s  %16s' % ('----', '--', '----')
 
    print headerStr
    print borderStr
   

    for l in locks:
        valStr = '%-20s  %16lu  %16lx' % (l.get_name(), l.get_label_id(), uhex(l.get_lock()))
        for col in PRINT_COLS:
            valStr += '  %16s' % get_col_value(l, col)
        print valStr
        continue

            
        tids = l.get_tids()
        tidsPercent = ''
        totPercent = (l.get_exclusive_hold_time() * 100.0) / float(duration)
        for tid in tids.keys():
            tidSet[tid] = 1
            time = tids[tid]
            tidsPercent += '%lu:%.2f%% ' % (tid, (time * 100.0) / l.get_exclusive_hold_time())

        cpuTable = l.get_cpus()
        cpus = cpuTable.keys()
        time = cpuTable[cpus[0]]
        cpuString = '%u:%.2f%%' % (cpus[0], (time * 100.0) / l.get_exclusive_hold_time())
        for cpu in cpus[1:]:
            time = cpuTable[cpu]
            cpuString += ' %u:%.2f%%' % (cpu, (time * 100.0) / l.get_exclusive_hold_time())

        pcs = l.get_pcs()
        pc = sorted(pcs.keys(), key=lambda k: pcs[k], reverse=True)[0]
        #print pcs
        #print pc
        print '%-20s  %16lu  %16lx  %16lx  %12lu  %8.2f    %-36s  %-s' % (l.get_name(), 
                                                                          l.get_label_id(), 
                                                                          uhex(l.get_lock()),
                                                                          uhex(pc),
                                                                          l.get_exclusive_hold_time(),
                                                                          totPercent,
                                                                          cpuString,
                                                                          tidsPercent)

    # Print TID strings
    print '\n'
    print '%-20s  %16s' % ('tid', 'name')
    print '%-20s  %16s' % ('---', '----')
    conn = sqlite3.connect(dbFile)
    c = conn.cursor()
    tmpl = 'SELECT str FROM %s_tasks WHERE tid = %s'
    for tid in tidSet.keys():
        q = tmpl % (dataName, tid)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        if len(rs) == 0:
            print '%-20s              %s' % (tid, '(unknown)')
        else:
            print '%-20s              %s' % (tid, rs[0][0])


if __name__ == "__main__":
    sys.exit(main())
