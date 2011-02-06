#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex
from mtracepy.addr2line import Addr2Line
import sqlite3
import sys

DEFAULT_FILTERS         = []
DEFAULT_COLS            = ['pc', 'length', 'percent']
DEFAULT_ADDR2LINE       = None
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
    -print col -exefile exefile ]

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

    'exefile' is the executable for which addresses should be translated
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

    def exefile_handler(filepath):
        global DEFAULT_ADDR2LINE
        DEFAULT_ADDR2LINE = Addr2Line(filepath)

    handler = {
        '-filter-label'  : filter_label_handler,
        '-filter-tid-count' : filter_tid_count_handler,
        '-filter-cpu-count' : filter_cpu_count_handler,
        '-print' : print_handler,
        '-exefile' : exefile_handler
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
        pc = sorted(pcs.keys(), key=lambda k: pcs[k][0], reverse=True)[0]
        pc = '%016lx' % uhex(pc)
        if DEFAULT_ADDR2LINE:
            s = '  %s  %-64s  %s' % (pc, 
                                     DEFAULT_ADDR2LINE.file(pc) + ':' + DEFAULT_ADDR2LINE.line(pc),
                                     DEFAULT_ADDR2LINE.func(pc))
            return s
        else:
            return pc
       
    def get_length():
        return str(lock.get_exclusive_hold_time())

    def get_percent():
        return '%.2f' % ((lock.get_exclusive_hold_time() * 100.0) / SUMMARY.maxWork)

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
        totPercent = (lock.get_exclusive_hold_time() * 100.0) / float(SUMMARY.maxWork)
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
    

def amdahlScale(p, n):
    return (1.0 / ((1.0 - p) + (p / n)))

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
    
    tidSet = {}

    locks = mtracepy.lock.get_locks(dbFile, dataName)
    locks.extend(mtracepy.harcrit.get_harcrits(dbFile, dataName));
    locks = sorted(locks, key=lambda l: l.get_exclusive_hold_time(), reverse=True)
    locks = apply_filters(locks, DEFAULT_FILTERS)

    headerStr = '%-40s  %16s  %16s' % ('name', 'id', 'lock')
    borderStr = '%-40s  %16s  %16s' % ('----', '--', '----')
    for col in PRINT_COLS:
        headerStr += '  %16s' % col
        borderStr += '  %16s' % '----'
 
    print headerStr
    print borderStr

    maxHoldTime = 0
    for l in locks:
        if maxHoldTime < l.get_exclusive_hold_time():
            maxHoldTime = l.get_exclusive_hold_time()
        valStr = '%-40s  %16lu  %16lx' % (l.get_name(), l.get_label_id(), uhex(l.get_lock()))
        for col in PRINT_COLS:
            valStr += '  %16s' % get_col_value(l, col)
        print valStr

    maxSerial = float(maxHoldTime) / float(SUMMARY.maxWork)
    maxAmdahl = 1.0 / (float(maxHoldTime) / float(SUMMARY.maxWork))
    minAmdahl = (float(SUMMARY.minWork) / float(SUMMARY.maxWork)) * maxAmdahl
    
    print 'max amdahl %.2f' % maxAmdahl
    print 'min amdahl %.2f' % minAmdahl
    print '#%s\t%s\t%s' % ('core', 'min', 'max')
    for i in range(2, 49):
        amMax = amdahlScale(1 - maxSerial, i)
        amMin = (float(SUMMARY.minWork) / float(SUMMARY.maxWork)) * amMax
        print '%u\t%f\t%f' % (i, amMin, amMax)

if __name__ == "__main__":
    sys.exit(main())
