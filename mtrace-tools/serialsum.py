#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex, checksum
from mtracepy.addr2line import Addr2Line
from mtracepy.serial import MtraceSerials
import sqlite3
import sys
import pickle
import os
import errno

DEFAULT_FILTERS         = []
DEFAULT_COLS            = ['pc', 'length', 'percent']
DEFAULT_ADDR2LINE       = None
PRINT_COLS              = []
SUMMARY                 = None
DEFAULT_NUM_CORES       = 2

class FilterLabel(object):
    def __init__(self, labelName):
        self.labelName = labelName

    def filter(self, lock):
        return self.labelName != lock.get_name()

class FilterTidCount(object):
    def __init__(self, count):
        self.count = count

    def filter(self, lock):
        return len(lock.get_tids()) > self.count

class FilterCpuCount(object):
    def __init__(self, count):
        self.count = count

    def filter(self, lock):
        return len(lock.get_cpus()) > self.count

class FilterCpuPercent(object):
    def __init__(self, percent):
        self.percent = percent

    def filter(self, lock):
        cpuTable = lock.get_cpus()
        cpus = cpuTable.keys()
        for cpu in cpus:
            time = cpuTable[cpu].time(DEFAULT_NUM_CORES)
            percent = (time * 100.0) / lock.get_exclusive_stats().time(DEFAULT_NUM_CORES)
            if percent > self.percent:
                return False
        return True

def usage():
    print """Usage: serialsum.py DB-file name [ -filter-label filter-label 
    -filter-tid-count filter-tid-count -filter-cpu-count filter-cpu-count 
    -print col -exefile exefile -num-cores num-cores]

    'filter-tid-count' is the number of TIDs minus one that must execute
      a serial section

    'filter-cpu-count' is the number of CPUs minus one that must execute
      a serial section

    'filter-cpu-percent'

    'col' is the name of a column.  Valid values are:
      'pc'      --
      'length'  --
      'percent' --
      'cpus'    --
      'tids'    --

    'exefile' is the executable for which addresses should be translated
    
    'num-cores' is the number of cores to use
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

    def filter_cpu_percent_handler(percent):
        global DEFAULT_FILTERS
        DEFAULT_FILTERS.append(FilterCpuPercent(float(percent)))

    def print_handler(col):
        global PRINT_COLS
        PRINT_COLS.append(col)

    def exefile_handler(filepath):
        global DEFAULT_ADDR2LINE
        DEFAULT_ADDR2LINE = Addr2Line(filepath)

    def num_cores_handler(ncores):
        global DEFAULT_NUM_CORES
        DEFAULT_NUM_CORES = int(ncores)

    handler = {
        '-filter-label'         : filter_label_handler,
        '-filter-tid-count'     : filter_tid_count_handler,
        '-filter-cpu-count'     : filter_cpu_count_handler,
        '-filter-cpu-percent'   : filter_cpu_percent_handler,
        '-print'                : print_handler,
        '-exefile'              : exefile_handler,
        '-num-cores'            : num_cores_handler
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
        pc = sorted(pcs.keys(), key=lambda k: pcs[k].time(DEFAULT_NUM_CORES), reverse=True)[0]
        pc = '%016lx' % uhex(pc)
        if DEFAULT_ADDR2LINE:
            s = '  %s  %-64s  %s' % (pc, 
                                     DEFAULT_ADDR2LINE.file(pc) + ':' + DEFAULT_ADDR2LINE.line(pc),
                                     DEFAULT_ADDR2LINE.func(pc))
            return s
        else:
            return pc
       
    def get_length():
        return str(lock.get_exclusive_stats().time(DEFAULT_NUM_CORES))

    def get_percent():
        return '%.2f' % ((lock.get_exclusive_stats().time(DEFAULT_NUM_CORES) * 100.0) / SUMMARY.get_max_work(DEFAULT_NUM_CORES))

    def get_cpus():
        cpuTable = lock.get_cpus()
        cpus = cpuTable.keys()
        time = cpuTable[cpus[0]].time(DEFAULT_NUM_CORES)
        cpuString = '%u:%.2f%%' % (cpus[0], (time * 100.0) / lock.get_exclusive_stats().time(DEFAULT_NUM_CORES))
        for cpu in cpus[1:]:
            time = cpuTable[cpu].time(DEFAULT_NUM_CORES)
            cpuString += ' %u:%.2f%%' % (cpu, (time * 100.0) / lock.get_exclusive_stats().time(DEFAULT_NUM_CORES))
        return cpuString

    def get_tids():
        tids = lock.get_tids()
        tidsPercent = ''
        totPercent = (lock.get_exclusive_stats().time(DEFAULT_NUM_CORES) * 100.0) / float(SUMMARY.get_max_work(DEFAULT_NUM_CORES))
        for tid in tids.keys():
            time = tids[tid]
            tidsPercent += '%lu:%.2f%% ' % (tid, (time * 100.0) / lock.get_exclusive_stats().time(DEFAULT_NUM_CORES))
        return tidsPercent

    colValueFuncs = {
        'pc'      : get_pc,
        'length'  : get_length,
        'percent' : get_percent,
        'cpus'    : get_cpus,
        'tids'    : get_tids
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
    SUMMARY = mtracepy.model.MtraceSummary(dbFile, dataName)

    serials = MtraceSerials.open(dbFile, dataName, '.')
    filtered = serials.filter(DEFAULT_FILTERS)
    sortedFiltered = sorted(filtered, 
                            key=lambda l: l.get_exclusive_stats().time(DEFAULT_NUM_CORES), 
                            reverse=True)

    headerStr = '%-40s  %16s  %16s' % ('name', 'id', 'lock')
    borderStr = '%-40s  %16s  %16s' % ('----', '--', '----')
    for col in PRINT_COLS:
        headerStr += '  %16s' % col
        borderStr += '  %16s' % '----'
 
    print headerStr
    print borderStr

    for s in sortedFiltered:
        valStr = '%-40s  %16lu  %16lx' % (s.get_name(), s.get_label_id(), uhex(s.get_lock()))
        for col in PRINT_COLS:
            valStr += '  %16s' % get_col_value(s, col)
        print valStr

    serials.close('.')

if __name__ == "__main__":
    sys.exit(main())
