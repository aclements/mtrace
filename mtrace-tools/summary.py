#!/usr/bin/python

from mtracepy import typedesc
from mtracepy.syscall import CallSummary
from mtracepy.util import *

import sqlite3
import sys
import os.path
import pickle
import errno
import hashlib
import json

default_sort            = 'sum-inst'
default_print           = [ 'sum-inst', 'sum-type', 'unique-clines' ]
default_pickledir       = 'summary-pkl'
default_type_print      = 5
default_inst_print      = 5
default_filters         = [ ]
default_divisor         = 1

the_print_columns       = []

# XXX there must be a better way..
def uhex(i):
    return (i & 0xffffffffffffffff)

def checksum(fileName):
    f = open(fileName,"rb")
    m = hashlib.md5()
    d = f.read()
    m.update(d)
    f.close()
    return m.digest()

class FilterLabel:
    def __init__(self, labelName):
        self.labelName = labelName

    def filter(self, summaryObject):
        return self.labelName != summaryObject.name

class FilterAllocPc:
    def __init__(self, allocPc):
        self.allocPc = allocPc

    def filter(self, summaryObject):
        s = '%lx' % uhex(summaryObject.allocPc)
        return self.allocPc != s

class FilterEntry:
    def __init__(self, entryName):
        self.entryName = entryName

    def filter(self, summaryObject):
        return self.entryName != summaryObject.entryName

class MtraceSummary:
    def __init__(self, dbFile, name):
        # Descending order based on count
        self.call_summary = []
        self.dataName = name
        self.dbFile = dbFile
        self.csum = None

        count_calls = 'SELECT pc, COUNT(*) FROM %s_call_traces GROUP BY pc ORDER BY COUNT(*) DESC' % name

        conn = sqlite3.connect(dbFile)
        c = conn.cursor()
        c.execute(count_calls)
        for row in c:
            pc = int(row[0])
            count = int(row[1])

            self.call_summary.append(CallSummary(dbFile, name, pc))

        conn.close()

    @staticmethod
    def open(dbFile, dataName, pickleDir):
        base, ext = os.path.splitext(dbFile)
        base = os.path.basename(base)
        picklePath = pickleDir + '/' + base + '-' + dataName + '.pkl'
        
        stats = None
        try:
            pickleFile = open(picklePath, 'r')
            stats = pickle.load(pickleFile)

            if stats.dataName != dataName:
                raise Exception('unexpected dataName')
            if stats.csum != checksum(dbFile):
                raise Exception('checksum mismatch: stale pickle?')

            # This following members are ephemeral
            stats.dbFile = dbFile

            pickleFile.close()
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            stats = MtraceSummary(dbFile, dataName)

        return stats

    def close(self, pickleDir):
        if self.csum == None:
            self.csum = checksum(self.dbFile)

        base, ext = os.path.splitext(self.dbFile)
        base = os.path.basename(base)
        picklePath = pickleDir + '/' + base + '-' + self.dataName + '.pkl'
       
        output = open(picklePath, 'wb')
        pickle.dump(self, output)
        output.close()

    def sort(self, sortType):

        def call_count_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_call_count(), 
                          reverse=True)

        def precise_call_count_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_precise_call_count(), 
                          reverse=True)

        def inst_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_total_unique_obj(), 
                          reverse=True)

        def type_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_total_unique_type(), 
                          reverse=True)

        sortFuncs = {
            'precise-call-count' : precise_call_count_handler,
            'call-count' : call_count_handler,
            'sum-inst'   : inst_handler,
            'sum-type'   : type_handler
        }

        self.call_summary = sortFuncs[sortType]()

    def set_filters(self, filters):
        for cs in self.call_summary:
            cs.set_filters(filters)

    def print_summary(self, printCols):
        print 'summary'
        print '-------'

        s = '  %-24s' % 'name'

        for col in printCols:
            s += ' %16s' % col
        s += '\n'

        s += '  %-24s' % '----'
        for col in printCols:
            s += ' %16s' % '----'
        s += '\n'

        for cs in self.call_summary:
            s += '  %-24s' % cs.get_str_name()
            for col in printCols:
                f = cs.get_col_value(col)
                if round(f) == f:
                    s += ' %16lu' % f
                else:
                    s += ' %16.2f' % f
            s += '\n'

        print s

    def print_top_objs(self, numPrint):
        print 'inst summary'
        print '------------'

        for cs in self.call_summary:
            if cs.get_total_unique_obj() == 0:
                continue

            print '  name=%s ' % ( cs.get_str_name() )
            print '  ----'

            for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
                if labelType == mtrace_label_block:
                    continue
                if cs.get_unique_obj(labelType) == 0:
                    continue

                print '    type=%s' % ( mtrace_label_str[labelType] )
                print '    ----'

                print '      %-20s %16s %16s %16s %16s' % ('name', 'alloc_pc', 'count', 'tids', 'id')
                print '      %-20s %16s %16s %16s %16s' % ('----', '--------', '-----', '----', '--')

                top = cs.get_top_objs(labelType)
                for higher in top[0:numPrint]:
                    print '      %-20s %016lx %16u %16u %16u' % (higher.d.get_label_str(), 
                                                                 higher.d.get_alloc_pc(), 
                                                                 higher.count, 
                                                                 higher.tids,
                                                                 higher.d.labelId)
                print ''

    def print_top_types(self, numPrint):
        print 'type summary'
        print '------------'

        for cs in self.call_summary:
            if cs.get_total_unique_type() == 0:
                continue

            print '  name=%s ' % ( cs.get_str_name() )
            print '  ----'

            for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
                if labelType == mtrace_label_block:
                    continue
                if cs.get_unique_type(labelType) == 0:
                    continue

                print '    type=%s' % ( mtrace_label_str[labelType] )
                print '    ----'

                print '      %-20s %16s %16s' % ('name', 'count', 'inst')
                print '      %-20s %16s %16s' % ('----', '-----', '----')

                top = cs.get_top_types(labelType)
                for higher in top[0:numPrint]:
                    print '      %-20s %16u %16u' % (higher.name, 
                                                     higher.count,
                                                     higher.instanceNum)
                print ''


    def print_miss_per_types_json(self, numPrint):
        xxxHack = [ 'stub_clone', 'sys_exit_group', 'sys_wait4', 'sys_read', 'sys_open' ]

        callDict = {}
        for cs in self.call_summary:
            if cs.get_total_unique_type() == 0:
                continue
            if xxxHack.count(cs.get_str_name()) == 0:
                continue

            typeList = []
            for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
                if labelType == mtrace_label_block:
                    continue
                if cs.get_unique_type(labelType) == 0:
                    continue

                top = cs.get_top_types(labelType)
                toSort = []
                for higher in top[0:numPrint]:
                    entryDict = { 'name' : higher.name,
                                  'miss_per_type' : cs.miss_per_type(labelType, higher.name),
                                  'locked_sections' : cs.locked_section_per_type(labelType, higher.name) }
                    toSort.append(entryDict)

                typeList.extend(toSort)

            typeList = sorted(typeList, key=lambda e: e['miss_per_type'], reverse=True)
            callDict[cs.get_str_name()] = typeList
        print json.dumps(callDict)

    def print_miss_per_types(self, numPrint):
        print 'miss-per-type summary'
        print '---------------------'

        xxxHack = [ 'stub_clone', 'sys_exit_group', 'sys_wait4', 'sys_read', 'sys_open' ]

        for cs in self.call_summary:
            if cs.get_total_unique_type() == 0:
                continue
            if xxxHack.count(cs.get_str_name()) == 0:
                continue

            print '  name=%s ' % ( cs.get_str_name() )
            print '  ----'

            for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
                if labelType == mtrace_label_block:
                    continue
                if cs.get_unique_type(labelType) == 0:
                    continue

                print '    type=%s' % ( mtrace_label_str[labelType] )
                print '    ----'

                print '      %-20s %16s' % ('name', 'miss-per-type')
                print '      %-20s %16s' % ('----', '-------------')

                top = cs.get_top_types(labelType)
                toSort = []
                for higher in top[0:numPrint]:
                    toSort.append([higher.name, cs.miss_per_type(labelType, higher.name), 
                                   cs.locked_section_per_type(labelType, higher.name)])

                toSort = sorted(toSort, key=lambda e: e[1], reverse=True)
                for e in toSort:
                    print '      %-20s %13.2f' % (e[0], e[1])
                print ''

    def print_all_types(self, divisor = 1):
        tmpDict = {}
        numCols = 1

        for cs in self.call_summary:
            for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
                if labelType == mtrace_label_block:
                    continue
                top = cs.get_top_objs(labelType)
                for higher in top:
                    count = higher.count
                    if higher.d.get_label_str() in tmpDict:
                        count += tmpDict[higher.d.get_label_str()]
                    tmpDict[higher.d.get_label_str()] = count

        typeNames = tmpDict.keys()

        typeDesc = []
        for typeName in typeNames:
            count = tmpDict[typeName]
            typeDesc.append(typedesc.TypeDescription(typeName, count = count))

        typeDesc = sorted(typeDesc, key=lambda k: k.count, reverse=True)

        n = 0
        for desc in typeDesc:
            if n != 0 and n % numCols == 0:
                print ''
            s = "  %-32s  %16lu  %s" % (desc.typeName, desc.count / divisor, desc.description())
            print s,
            n += 1

def summarize_types(stats):
    stats.print_all_types(divisor = default_divisor)
    return

def summarize_all(stats):
    printCols = the_print_columns
    if len(printCols) == 0:
        printCols = default_print

    stats.print_summary(printCols)

    if default_inst_print != 0:
        stats.print_top_objs(default_inst_print)
    if default_type_print != 0:
        stats.print_top_types(default_type_print)

def summarize_brief(stats):
    printCols = the_print_columns
    if len(printCols) == 0:
        printCols = default_print

    stats.print_summary(printCols)

def summarize_miss_per_types(stats):
    stats.print_miss_per_types_json(default_type_print)

default_summarize = summarize_all

summarize_types = {
    'types' : summarize_types,
    'miss-per-types' : summarize_miss_per_types,
    'brief' : summarize_brief,
    'all'   : summarize_all
}

def parse_args(argv):
    args = argv[3:]

    def sort_handler(val):
        global default_sort
        default_sort = val

    def print_handler(val):
        global the_print_columns
        the_print_columns.append(val)

    def pickledir_handler(val):
        global default_pickledir
        default_pickledir = val

    def numprint_handler(val):
        global default_inst_print
        global default_type_print
        default_inst_print = int(val)
        default_type_print = int(val)

    def filterlabel_handler(val):
        global default_filters
        ig = FilterLabel(val)
        default_filters.append(ig)

    def filterpc_handler(val):
        global default_filters
        ig = FilterAllocPc(val)
        default_filters.append(ig)

    def fliterentry_handler(val):
        global default_filters
        ig = FilterEntry(val)
        default_filters.append(ig)

    def summarize_handler(val):
        global default_summarize
        default_summarize = summarize_types[val]

    def divisor_handler(val):
        global default_divisor
        default_divisor = int(val)

    handler = {
        '-sort'         : sort_handler,
        '-print'        : print_handler,
        '-pickledir'    : pickledir_handler,
        '-numprint'     : numprint_handler,
        '-filterlabel'  : filterlabel_handler,
        '-filterpc'     : filterpc_handler,
        '-filterentry'  : fliterentry_handler,
        '-summarize'    : summarize_handler,
        '-divisor'      : divisor_handler
    }

    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])

def usage():
    print """Usage: summary.py DB-file name [ -sort col -print col 
    -pickledir pickledir -numprint numprint -filterlabel filterlabel 
    -filterpc filterpc -filterentry filterentry -summarize summarize 
    -divisor divisor]

    'col' is the name of a column.  Valid values are:
      'heap-inst'    -- heap allocated object instances
      'block-inst'   -- block allocated objects instances
      'static-inst'  -- statically allocated object instances
      'percpu-inst'  -- per-cpu object instances
      'sum-inst'     -- the sum of heap-inst, static-inst, and percpu-inst
      'heap-type'    -- heap allocated object types
      'block-type'   -- block allocated object types
      'static-type'  -- statically allocated object types
      'percpu-type'  -- per-cpu object types
      'sum-type'     -- the sum of heap-type, static-type, and percpu-type
      'unique-clines' -- unique cache lines
      'all-clines'   -- all cache lines
      'per-call-clines' -- average per call cache lines
      'call-count'   -- the syscall invocation count

    'pickledir' is the name of a directory to read and write pickled 
      summaries from and to

    'numprint' is the number of rows to print for the inst and type
      summaries (the default is 5)

    'filterlabel' is a label name to filter from the summary

    'filterpc' is the alloc pc to filter fro the summary

    'filterentry' is the name of a kernel entry point to filter

    'summarize' is the type of summary to print.  Valid value are:
      'types'        -- print a type summary
      'brief'        -- print kernel call summary
      'all'          -- the default

    'divisor' is an integer to divide sums by
"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage()

    if os.path.isfile(argv[1]) == False:
        print argv[1] + ' does not exist'
        exit(1)

    dbFile = argv[1]
    dataName = argv[2]

    parse_args(argv)

    stats = MtraceSummary.open(dbFile, dataName, default_pickledir)

    stats.set_filters(default_filters)    
    stats.sort(default_sort)

    default_summarize(stats)
    stats.close(default_pickledir)
    return

if __name__ == "__main__":
    sys.exit(main())
