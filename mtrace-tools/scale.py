#!/usr/bin/python

import mtracepy.lock
import mtracepy.harcrit
import mtracepy.summary
from mtracepy.util import uhex, checksum
from mtracepy.addr2line import Addr2Line
import sqlite3
import sys
from mtracepy.serial import MtraceSerials
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

def amdahlScale(p, n):
    return (1.0 / ((1.0 - p) + (p / n)))


def print0(summary, serials):
    print '#%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('cpu', 'min amdahl', 'max amdahl', 'min scale', 'max scale', 'serial %', 'name')
    print '%u\t%f\t%f' % (1, 1.0, 1.0)

    maxWork = float(summary.get_max_work(1))
    minWork = float(summary.get_min_work(1))

    for i in range(2, 49):
        maxSample = None
        for s in serials:
            if maxSample == None or maxSample.get_exclusive_stats().time(i) < s.get_exclusive_stats().time(i):
                maxSample = s

        maxHoldTime = maxSample.get_exclusive_stats().time(i)
        maxSerial = float(maxHoldTime) / maxWork
        maxAmdahl = 1.0 / (float(maxHoldTime) / maxWork)
        minAmdahl = (minWork / maxWork) * maxAmdahl
        amMax = amdahlScale(1 - maxSerial, i)
        amMin = (minWork / maxWork) * amMax
        print '%u\t%f\t%f\t%f\t%f\t%f\t%s' % (i, minAmdahl, maxAmdahl, amMin, amMax, maxSerial, maxSample.get_name())

def print1(summary, serials):
    print '#%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('cpu', 'min amdahl', 'max amdahl', 'min scale', 'max scale', 'serial %', 'name')
    print '%u\t%f\t%f' % (1, 1.0, 1.0)

    maxWork = float(summary.get_max_work(1))
    minWork = float(summary.get_min_work(1))

    for i in range(2, 49):
        maxSample = None
        for s in serials:
            if maxSample == None or maxSample.get_exclusive_stats().time(i) < s.get_exclusive_stats().time(i):
                maxSample = s

        maxHoldTime = maxSample.get_exclusive_stats().time(i)
        maxSerial = float(maxHoldTime) / maxWork
        maxAmdahl = 1.0 / (float(maxHoldTime) / maxWork)
        minAmdahl = (minWork / maxWork) * maxAmdahl
        amMax = amdahlScale(1 - maxSerial, i)
        #amMin = (minWork / maxWork) * amMax
        sup = (float(summary.get_min_work(1)) / ((float(summary.get_max_work(i)) - float(maxHoldTime))/ float(i)))
        amMin = 1 / (maxSerial + ((1 - maxSerial) / sup))
        print '%u\t%f\t%f\t%f\t%f\t%f\t%s' % (i, minAmdahl, maxAmdahl, amMin, amMax, maxSerial, maxSample.get_name())

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage(argv)

    dbFile = argv[1]
    dataName = argv[2]
    parse_args(argv)

    summary = mtracepy.model.MtraceSummary(dbFile, dataName)

    serials = MtraceSerials.open(dbFile, dataName, '.')
    filtered = serials.filter(DEFAULT_FILTERS)

    print0(summary, filtered)
    serials.close('.')

if __name__ == "__main__":
    sys.exit(main())
