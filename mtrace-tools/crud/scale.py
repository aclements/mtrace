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

class FilterCpuPercent(object):
    def __init__(self, percent):
        self.percent = percent

    def filter(self, lock):
        cpuTable = lock.get_cpus()
        cpus = cpuTable.keys()
        for cpu in cpus:
            time = cpuTable[cpu].time(1)
            percent = (time * 100.0) / lock.get_exclusive_stats().time(1)
            if percent > self.percent:
                return False
        return True

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

    def filter_cpu_percent_handler(percent):
        global DEFAULT_FILTERS
        DEFAULT_FILTERS.append(FilterCpuPercent(float(percent)))

    handler = {
        '-filter-label'  : filter_label_handler,
        '-filter-tid-count' : filter_tid_count_handler,
        '-filter-cpu-count' : filter_cpu_count_handler,
        '-filter-cpu-percent'   : filter_cpu_percent_handler
    }

    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])

def amdahlScale(p, n):
    return (1.0 / ((1.0 - p) + (p / n)))


def print0(summary, serials):
    print '#%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('cpu', 'min scale', 'max scale', 'min amdahl', 'max amdahl', 'serial %', 'name')
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
        print '%u\t%f\t%f\t%f\t%f\t%f\t%s' % (i, amMin, amMax, maxSerial, minAmdahl, maxAmdahl, maxSample.get_name())

def print1(summary, serials):
    print '#%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('cpu', 'min scale', 'max scale', 'min sup', 'max sup', 'serial %', 'name')
    print '%u\t%f\t%f' % (1, 1.0, 1.0)

    for i in range(2, 49):
        maxSample = None
        for s in serials:
            if maxSample == None or maxSample.get_exclusive_stats().time(i) < s.get_exclusive_stats().time(i):
                maxSample = s

        maxHoldTime = maxSample.get_exclusive_stats().time(i)
        maxSerial = float(maxHoldTime) / float(summary.get_max_work(i))

        minSingle = float(summary.get_min_work(1)) - maxSample.get_exclusive_stats().time(1)
        maxSingle = float(summary.get_max_work(1)) - maxSample.get_exclusive_stats().time(1)
        maxParallel = ((float(summary.get_max_work(i)) - float(maxHoldTime)) / float(i))

        minSup = (minSingle / maxParallel)
        maxSup = (maxSingle / maxParallel)

        amMin = 1 / (maxSerial + ((1 - maxSerial) / minSup))
        amMax = 1 / (maxSerial + ((1 - maxSerial) / maxSup))

        print '%u\t%f\t%f\t%f\t%f\t%f\t%s' % (i, amMin, amMax, minSup, maxSup, maxSerial, maxSample.get_name())

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

    print1(summary, filtered)
    serials.close('.')

if __name__ == "__main__":
    sys.exit(main())
