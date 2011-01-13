#!/usr/bin/python

from mtracepy import typedesc
import sqlite3
import sys
import os.path
import pickle
import errno
import hashlib

default_sort            = 'sum-inst'
default_print           = [ 'sum-inst', 'sum-type', 'clines' ]
default_pickledir       = '.'
default_type_print      = 5
default_inst_print      = 5
default_filters         = [ ]
default_divisor         = 1

mtrace_label_heap       = 1
mtrace_label_block      = 2
mtrace_label_static     = 3
mtrace_label_percpu     = 4

mtrace_label_str        =  { mtrace_label_heap   : 'heap',
                             mtrace_label_block  : 'block',
                             mtrace_label_static : 'static',
                             mtrace_label_percpu : 'percpu' }

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

class InstanceSummary:
    def __init__(self, name, allocPc, count, labelId, entryName):
        self.name = name
        self.allocPc = allocPc
        self.count = count
        self.labelId = labelId
        self.entryName = entryName

class TypeSummary:
    def __init__(self, name, count, instanceNum):
        self.name = name
        self.count = count
        self.instanceNum = instanceNum

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

class CallSummary:
    def __init__(self, dbFile, name, pc):
        self.pc = pc
        self.name = name
        self.dbFile = dbFile

        self.filters = []
        self.csum = None
        self.conn = None
        self.sysName = None
        self.count = None
        self.uniqueCline = None
        self.uniqueObj = {}
        self.topObjs = {}
        self.uniqueType = {}

    def __getstate__(self):
        odict = self.__dict__.copy()
        # This following members are ephemeral
        del odict['conn']
        del odict['filters']
        return odict

    def __setstate__(self, dict):
        self.__dict__.update(dict)
        self.conn = None
        self.filters = []

    def set_filters(self, filters):
        self.filters = filters

    def apply_filters(self, lst):
        if len(self.filters) > 0:
            lst2 = []
            for e in lst:
                lst2.append(e)
                for f in self.filters:
                    if f.filter(e) == False:
                        lst2.pop()
                        break
            return lst2
        else:
            return lst

    def get_conn(self):
        if self.conn == None:
            self.conn = sqlite3.connect(self.dbFile)
        return self.conn

    def get_call_count(self):
        if self.count == None:
            # XXX there might be multiple fcalls per function invocation
            q = 'SELECT COUNT(*) FROM %s_call_traces where pc = %ld' % (self.name, self.pc)
            c = self.get_conn().cursor()
            c.execute(q)            
            rs = c.fetchall()
            if len(rs) != 1:
                raise Exception('unexpected result')
            self.count = rs[0][0]

        return self.count

    def get_sys_name(self):
        if self.sysName == None:
            q = 'SELECT DISTINCT name FROM %s_call_traces where pc = %ld' % (self.name, self.pc)
            c = self.get_conn().cursor()
            c.execute(q)            
            rs = c.fetchall()
            if len(rs) != 1:
                raise Exception('unexpected result')
            self.sysName = rs[0][0]
        
        return self.sysName

    def get_str_name(self):
        n = self.get_sys_name()
        if n == '(unknown)':
            n = str(uhex(self.pc))
        return n

    def get_unique_cline(self):
        if self.uniqueCline == None:
            q = 'SELECT COUNT(DISTINCT guest_addr) FROM %s_accesses WHERE EXISTS ' + \
                '(SELECT * FROM %s_call_traces WHERE ' + \
                '%s_call_traces.cpu = %s_accesses.cpu ' + \
                'AND %s_call_traces.call_trace_tag = %s_accesses.call_trace_tag ' + \
                'AND %s_call_traces.pc = %ld)'

            q = q % (self.name, self.name,
                     self.name, self.name,
                     self.name, self.name,
                     self.name, self.pc)
            c = self.get_conn().cursor()
            c.execute(q)    
            rs = c.fetchall()
            if len(rs) != 1:
                raise Exception('unexpected result')
            self.uniqueCline = rs[0][0]
        
        return self.uniqueCline

    def get_total_unique_obj(self):
        s = 0
        for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
            if labelType == mtrace_label_block:
                continue
            s += self.get_unique_obj(labelType)

        return s

    def get_total_unique_type(self):
        s = 0
        for labelType in range(mtrace_label_heap, mtrace_label_percpu + 1):
            if labelType == mtrace_label_block:
                continue
            s += self.get_unique_type(labelType)

        return s

    def get_unique_obj(self, labelType):
        return len(self.get_top_objs(labelType))

    def get_unique_type(self, labelType):
        return len(self.get_top_types(labelType))

    def get_label_str(self, labelId, labelType):
        q = 'SELECT str FROM %s_labels%u WHERE label_id = %lu'
        q = q % (self.name, labelType, labelId)
        c = self.get_conn().cursor()
        c.execute(q)    
        rs = c.fetchall()        
        
        if len(rs) != 1:
            raise Exception('unexpected result')            

        return rs[0][0]

    def get_label_alloc_pc(self, labelId, labelType):
        q = 'SELECT alloc_pc FROM %s_labels%u WHERE label_id = %lu'
        q = q % (self.name, labelType, labelId)
        c = self.get_conn().cursor()
        c.execute(q)
        rs = c.fetchall()
        
        if len(rs) != 1:
            raise Exception('unexpected result')            

        return rs[0][0]

    def get_top_types(self, labelType):
        topObjs = self.get_top_objs(labelType)
        tmpDict = {}

        for higher in topObjs:
            typename = higher.name
            accessCount = higher.count

            if typename in tmpDict:
                entry = tmpDict[typename]
                entry.count += accessCount
                entry.instanceNum += 1
                tmpDict[typename] = entry
            else:
                tmpDict[typename] = TypeSummary(typename, accessCount, 1)

        return sorted(tmpDict.values(), key=lambda k: k.count, reverse=True)

    def get_top_objs(self, labelType):
        if labelType not in self.topObjs:
            tmpDict = {}

            q = 'SELECT DISTINCT label_id FROM %s_accesses WHERE label_type = %u ' + \
                'AND label_id != 0 AND EXISTS ' + \
                '(SELECT * FROM %s_call_traces WHERE ' + \
                '%s_call_traces.cpu = %s_accesses.cpu ' + \
                'AND %s_call_traces.call_trace_tag = %s_accesses.call_trace_tag ' + \
                'AND %s_call_traces.pc = %ld)'

            q = q % (self.name, labelType,
                     self.name,
                     self.name, self.name,
                     self.name, self.name,
                     self.name, self.pc)
            c = self.get_conn().cursor()
            c.execute(q)    
            rs = c.fetchall()
            for row in rs:
                labelId = row[0]
                q = 'SELECT COUNT(label_id) from %s_accesses where label_type = %u ' + \
                    'AND label_id = %u AND EXISTS ' + \
                    '(SELECT * FROM %s_call_traces WHERE ' + \
                    '%s_call_traces.cpu = %s_accesses.cpu ' + \
                    'AND %s_call_traces.call_trace_tag = %s_accesses.call_trace_tag ' + \
                    'AND %s_call_traces.pc = %ld)'
                q = q % (self.name, labelType,
                         labelId,
                         self.name,
                         self.name, self.name,
                         self.name, self.name,
                         self.name, self.pc)
                c = self.get_conn().cursor()
                c.execute(q)    

                rs2 = c.fetchall();

                if len(rs2) != 1:
                    raise Exception('unexpected result')            

                count = rs2[0][0]
                tmpDict[labelId] = InstanceSummary(self.get_label_str(labelId, labelType), 
                                                   self.get_label_alloc_pc(labelId, labelType), 
                                                   count,
                                                   labelId,
                                                   self.get_str_name())

            s = sorted(tmpDict.values(), key=lambda k: k.count, reverse=True)
            self.topObjs[labelType] = s

        return self.apply_filters(self.topObjs[labelType])

    def get_col_value(self, col):
        colValueFuncs = {
            'heap-inst'   : lambda: self.get_unique_obj(mtrace_label_heap),
            'block-inst'  : lambda: self.get_unique_obj(mtrace_label_block),
            'static-inst' : lambda: self.get_unique_obj(mtrace_label_static),
            'percpu-inst' : lambda: self.get_unique_obj(mtrace_label_percpu),
            'sum-inst'    : lambda: self.get_total_unique_obj(),

            'heap-type'   : lambda: self.get_unique_type(mtrace_label_heap),
            'block-type'  : lambda: self.get_unique_type(mtrace_label_block),
            'static-type' : lambda: self.get_unique_type(mtrace_label_static),
            'percpu-type' : lambda: self.get_unique_type(mtrace_label_percpu),
            'sum-type'    : lambda: self.get_total_unique_type(),

            'clines'      : lambda: self.get_unique_cline(),
            'call-count'  : lambda: self.get_call_count()
        }

        return colValueFuncs[col]()


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

        def inst_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_total_unique_obj(), 
                          reverse=True)

        def type_handler():
            return sorted(self.call_summary, 
                          key=lambda callSum: callSum.get_total_unique_type(), 
                          reverse=True)

        sortFuncs = {
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
                s += ' %16lu' % cs.get_col_value(col)
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

                print '      %-20s %16s %16s %16s' % ('name', 'alloc_pc', 'count', 'id')
                print '      %-20s %16s %16s %16s' % ('----', '--------', '-----', '--')

                top = cs.get_top_objs(labelType)
                for higher in top[0:numPrint]:
                    print '      %-20s %016lx %16u %16u' % (higher.name, 
                                                            uhex(higher.allocPc), 
                                                            higher.count, 
                                                            higher.labelId)
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
                    if higher.name in tmpDict:
                        count += tmpDict[higher.name]
                    tmpDict[higher.name] = count

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

default_summarize = summarize_all

summarize_types = {
    'types' : summarize_types,
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
      'clines'       -- unique cache lines
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
