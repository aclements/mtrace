#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex
import sqlite3
import sys

default_filters         = []

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
    -filter-tid-count filter-tid-count -filter-cpu-count filter-cpu-count ]
"""
    exit(1)

def parse_args(argv):
    args = argv[3:]

    def filter_label_handler(label):
        global default_filters
        default_filters.append(FilterLabel(label))

    def filter_tid_count_handler(count):
        global default_filters
        default_filters.append(FilterTidCount(int(count)))

    def filter_cpu_count_handler(count):
        global default_filters
        default_filters.append(FilterCpuCount(int(count)))

    handler = {
        '-filter-label'  : filter_label_handler,
        '-filter-tid-count' : filter_tid_count_handler,
        '-filter-cpu-count' : filter_cpu_count_handler
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
    parse_args(argv)

    summary = mtracepy.summary.MtraceSummary(dbFile, dataName)
    duration = summary.work
    
    tidSet = {}
    locks = mtracepy.lock.get_locks(dbFile, dataName)
    locks.extend(mtracepy.harcrit.get_harcrits(dbFile, dataName));
    locks = sorted(locks, key=lambda l: l.get_exclusive_hold_time(), reverse=True)
    locks = apply_filters(locks, default_filters)
    print '%-20s  %16s  %16s  %16s  %12s  %8s    %-36s  %-s' % (
        'name', 'id', 'lock', 'pc', 'serial', 'tot %', 'cpus %', 'tids %')
    print '%-20s  %16s  %16s  %16s  %12s  %8s    %-36s  %-s' % (
        '----', '--', '----', '--', '------', '-----', '------', '------')
    for l in locks:
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
