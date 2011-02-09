#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex, checksum
from mtracepy.addr2line import Addr2Line
import sqlite3
import sys
import pickle
import os
import errno

DEFAULT_FILTERS         = []

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

def usage(argv):
    print """Usage: serialsum.py DB-file name [ -filter-label filter-label 
    -filter-tid-count filter-tid-count -filter-cpu-count filter-cpu-count ]

    'filter-tid-count' is the number of TIDs minus one that must execute
      a serial section

    'filter-cpu-count' is the number of CPUs minus one that must execute
      a serial section
""" % argv[0],
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

    handler = {
        '-filter-label'  : filter_label_handler,
        '-filter-tid-count' : filter_tid_count_handler,
        '-filter-cpu-count' : filter_cpu_count_handler,
    }

    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])

class MtraceSerials:
    def __init__(self, dbFile, dataName):
        self.dataName = dataName
        self.dbFile = dbFile
        self.csum = None
        self.pickleOk = False

        self.serials = mtracepy.lock.get_locks(dbFile, dataName)
        self.serials.extend(mtracepy.harcrit.get_harcrits(dbFile, dataName));

    def filter(self, filters, persist = False):
        filtered = apply_filters(self.serials, filters)
        if persist:
            self.serials = filtered
        return filtered

    def close(self, pickleDir):
        if self.csum == None:
            self.csum = checksum(self.dbFile)
        if self.pickleOk:
            return

        base, ext = os.path.splitext(self.dbFile)
        base = os.path.basename(base)
        picklePath = pickleDir + '/' + base + '-' + self.dataName + '.pkl'
       
        output = open(picklePath, 'wb')
        pickle.dump(self, output)
        output.close()

def open_serials(dbFile, dataName, pickleDir):
    base, ext = os.path.splitext(dbFile)
    base = os.path.basename(base)
    picklePath = pickleDir + '/' + base + '-' + dataName + '.pkl'

    serials = None
    try:
        pickleFile = open(picklePath, 'r')
        serials = pickle.load(pickleFile)

        if serials.dataName != dataName:
            raise Exception('unexpected dataName')
        if serials.csum != checksum(dbFile):
            raise Exception('checksum mismatch: stale pickle?')

        # This following members are ephemeral
        serials.dbFile = dbFile
        serials.pickleOk = True

        pickleFile.close()
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        serials = MtraceSerials(dbFile, dataName)

    return serials


def amdahlScale(p, n):
    return (1.0 / ((1.0 - p) + (p / n)))

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage(argv)

    dbFile = argv[1]
    dataName = argv[2]
    parse_args(argv)

    summary = mtracepy.model.MtraceSummary(dbFile, dataName)
    serials = open_serials(dbFile, dataName, '.')
    filtered = serials.filter(DEFAULT_FILTERS)

    print '#%s\t%s\t%s\t%s\t%s\t%s' % ('cpu', 'min amdahl', 'max amdahl', 'min scale', 'max scale', 'serial %')
    print '%u\t%f\t%f' % (1, 1.0, 1.0)

    for i in range(2, 49):
        maxHoldTime = 0
        for s in filtered:
            if maxHoldTime < s.get_exclusive_stats().time(i):
                maxHoldTime = s.get_exclusive_stats().time(i)

        maxSerial = float(maxHoldTime) / float(summary.get_max_work(i))
        maxAmdahl = 1.0 / (float(maxHoldTime) / float(summary.get_max_work(i)))
        minAmdahl = (float(summary.get_min_work(i)) / float(summary.get_max_work(i))) * maxAmdahl
        amMax = amdahlScale(1 - maxSerial, i)
        amMin = (float(summary.get_min_work(i)) / float(summary.get_max_work(i))) * amMax
        print '%u\t%f\t%f\t%f\t%f\t%f' % (i, minAmdahl, maxAmdahl, amMin, amMax, maxSerial)

    serials.close('.')

if __name__ == "__main__":
    sys.exit(main())
