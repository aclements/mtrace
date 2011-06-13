import sqlite3

from util import *
from mtrace import MtraceInstanceDetail

def get_cline(addr):
    return uhex(addr) & (~63)

def get_miss_count(conn, dataName, syscallName, labelId, lockedDict):
    '''Returns how many unique cache lines form labelId 
    syscall named syscallName misses on'''

    q = '''SELECT DISTINCT call_trace_tag, guest_addr, locked_id from %s_accesses WHERE label_id = %lu
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
    guestClineSet = {}
    for row in c:
        tag = row['call_trace_tag']
        guestCline = get_cline(row['guest_addr'])
        lockedId = row['locked_id']

        if not tag in guestClineSet:
            guestClineSet[tag] = set()

        if not guestCline in guestClineSet[tag]:
            guestClineSet[tag].add(guestCline)
            if tag in tagDict:
                tagDict[tag] = tagDict[tag] + 1
            else:
                tagDict[tag] = 1

        if lockedId != 0:
            c2 = conn.cursor()
            q = 'SELECT str FROM %s_locked_sections WHERE id = %lu LIMIT 1' % (dataName, lockedId)
            c2.execute(q)
            nameList = c2.fetchall()
            if len(nameList) == 1:
                lockedName = nameList[0][0]
                if lockedName in lockedDict:
                    lockedDict[lockedName] = lockedDict[lockedName] + 1
                else:
                    lockedDict[lockedName] = 1
            else:
                print >> sys.stderr, 'oops: ' + nameList.__str__()             
            c2.close()
        else:
            if '0' in lockedDict:
                lockedDict['0'] = lockedDict['0'] + 1
            else:
                lockedDict['0'] = 1

    total = 0
    vals = tagDict.values()
    for count in vals:
        total += count

    return float(total)

class InstanceSummary:
    def __init__(self, dbFile, dataName, labelType, labelId, count, tids):
        self.d = MtraceInstanceDetail(dbFile,
                                      dataName,
                                      labelType,
                                      labelId)
        self.count = count
        self.tids = tids

class TypeSummary:
    def __init__(self, name, count, instanceNum):
        self.name = name
        self.count = count
        self.instanceNum = instanceNum

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
        self.allCline = None
        self.perCallCline = None
        self.callCount = None
        self.uniqueObj = {}
        self.topObjs = {}
        self.uniqueType = {}
        self.missPerType = {}

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
            self.conn.row_factory = sqlite3.Row
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

    def get_all_cline(self):
        if self.allCline == None:
            q = 'SELECT COUNT(guest_addr) FROM %s_accesses WHERE EXISTS ' + \
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
            self.allCline = rs[0][0]
        return self.allCline

    def get_per_call_cline(self):
        if self.perCallCline == None:
            q = 'SELECT DISTINCT call_trace_tag FROM %s_call_traces where pc = %ld'
            q = q % (self.name, self.pc)
            c = self.get_conn().cursor()
            c.execute(q)    
            line = 0
            call = 0
            for row in c:
                q = 'SELECT DISTINCT guest_addr FROM %s_accesses WHERE call_trace_tag = %lu and traffic = 1'
                tag = row[0]
                q = q % (self.name, tag)
                c2 = self.get_conn().cursor()
                c2.execute(q)
                guestClineSet = set()
                for guestAddr in c2:
                    guestCline = get_cline(guestAddr['guest_addr'])
                    if not guestCline in guestClineSet:
                        guestClineSet.add(guestCline)
                        line += 1
                call += 1

            self.perCallCline = line
            self.callCount = call
        return float(self.perCallCline) / float(self.callCount)

    def get_precise_call_count(self):
        if self.callCount == None:
            self.get_per_call_cline()
        return self.callCount

    def miss_per_type(self, labelType, labelName):
        if not labelName in self.missPerType:
            q = 'SELECT DISTINCT label_id FROM %s_labels%u WHERE str = \"%s\"'
            q = q % (self.name, labelType, labelName)
            c = self.get_conn().cursor()
            c.execute(q)
            total = 0
            lockedDict = {}
            for row in c:
                labelId = row[0]
                total += get_miss_count(self.conn, self.name, 
                                        self.get_sys_name(), 
                                        labelId, lockedDict)
            self.missPerType[labelName] = (float(total), lockedDict)

        return self.missPerType[labelName][0] / float(self.get_precise_call_count())

    def locked_section_per_type(self, labelType, labelName):
        self.miss_per_type(labelType, labelName)
        return self.missPerType[labelName][1]

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

    def get_tids(self, labelId, labelType):
        q = 'SELECT DISTINCT tid FROM %s_accesses WHERE label_id = %lu'
        q = q % (self.name, labelId)
        c = self.get_conn().cursor()
        c.execute(q)
        ret = []
        for r in c:
            ret.append(r[0])
        return ret

    def get_top_types(self, labelType):
        topObjs = self.get_top_objs(labelType)
        tmpDict = {}

        for higher in topObjs:
            typename = higher.d.get_label_str()
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
            for row in c:
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
                tmpDict[labelId] = InstanceSummary(self.dbFile,
                                                   self.name,
                                                   labelType,
                                                   labelId,
                                                   count,
                                                   len(self.get_tids(labelId, labelType)))

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

            'unique-clines': lambda: self.get_unique_cline(),
            'all-clines'   : lambda: self.get_all_cline(),
            'per-call-clines': lambda: self.get_per_call_cline(),
            'call-count'   : lambda: self.get_call_count(),
            'precise-call-count'   : lambda: self.get_precise_call_count()
        }

        return colValueFuncs[col]()
