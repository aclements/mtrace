import sqlite3
from util import uhex
import model
import copy

class MtraceSerialSection:
    
    def __init__(self, serialId, startTs, endTs, startCpu, read, tid, pc):
        self.serialId = serialId
        self.startTs = startTs
        self.endTs = endTs
        self.startCpu = startCpu
        self.tid = tid
        self.read = read
        self.pc = pc

    def __str__(self):
        return '%lu -- [%lu, %lu]' % (self.tid, self.startTs, self.endTs)

    def get_time(self):
        return self.endTs - self.startTs

class MtraceLock:
    
    def __init__(self, labelType, labelId, lock, dbFile, dataName, sampleClass):
        self.labelType = labelType
        self.labelId = labelId
        self.lock = lock
        self.dbFile = dbFile
        self.dataName = dataName
        self.sampleClass = sampleClass

        self.exclusive = None
        self.kerncalls = None
        self.name = None
        self.holdTime = None
        self.tids = None
        self.cpus = None
        self.pcs = None
        self.inited = False

    def __str__(self):
        return '%s:%lu:%lx' % (self.get_name(), self.labelId, uhex(self.lock))

    def __init_state(self):
        if self.inited:
            return

        self.cpus = {}
        self.tids = {}
        self.pcs = {}
        self.kerncalls = {}
        self.holdTime = 0
        self.exclusive = self.sampleClass(0, 0, 0, num = 0)

        self.holdTime = 0

        # Sections
        q = '''SELECT id, start_ts, end_ts, start_cpu, read, tid, pc, str, 
               locked_accesses, traffic_accesses, call_trace_tag FROM %s_locked_sections 
               WHERE label_id = %lu and lock = %lu and read <> 1'''
        q = q % (self.dataName,
                 self.labelId,
                 self.lock)
        conn = sqlite3.connect(self.dbFile)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(q)
        for row in c:
            if row[4] >= 1:
                continue

            section = MtraceSerialSection(row['id'], row['start_ts'], row['end_ts'], 
                                          row['start_cpu'], row['read'], row['tid'], row['pc'])

            agg = self.sampleClass(section.endTs - section.startTs,
                                   row['locked_accesses'],
                                   row['traffic_accesses'])

            self.exclusive.add(agg)

            if section.tid in self.tids:
                self.tids[section.tid].add(agg)
            else:
                self.tids[section.tid] = agg.copy()

            if section.startCpu in self.cpus:
                self.cpus[section.startCpu].add(agg)
            else:
                self.cpus[section.startCpu] = agg.copy()

            if section.pc in self.pcs:
                self.pcs[section.pc].add(agg)
            else:
                self.pcs[section.pc] = agg.copy()

            callTraceTag = row['call_trace_tag']
            if callTraceTag:
                if callTraceTag in self.kerncalls:
                    self.kerncalls[callTraceTag].add(agg)
                else:
                    self.kerncalls[callTraceTag] = agg.copy()

        # Name (label str and lock str)
        q = '''SELECT str FROM %s_locked_sections WHERE label_id = %lu and lock = %lu LIMIT 1'''
        q = q % (self.dataName,
                 self.labelId,
                 self.lock)
        c = conn.cursor()
        c.execute(q)
        lockStr = c.fetchone()['str']

        q = 'SELECT str FROM %s_labels%u WHERE label_id = %lu'
        q = q % (self.dataName,
                 self.labelType,
                 self.labelId)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        self.name = rs[0][0] + ':' + lockStr

        conn.close()
        self.inited = True

    def get_label_id(self):
        return self.labelId
    def get_lock(self):
        return self.lock
    def get_hold_time(self):
        self.__init_state()
        return self.holdTime
    def get_exclusive_stats(self):
        self.__init_state()
        return self.exclusive
    def get_name(self):
        self.__init_state()
        return self.name
    def get_tids(self):
        self.__init_state()
        return self.tids
    def get_cpus(self):
        self.__init_state()
        return self.cpus
    def get_pcs(self):
        self.__init_state()
        return self.pcs
    def get_kerncalls(self):
        self.__init_state()
        return self.kerncalls

def get_locks(dbFile, dataName):
    conn = sqlite3.connect(dbFile)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    q = 'SELECT DISTINCT label_type, label_id, lock, str FROM %s_locked_sections'
    q = q % (dataName)
    c.execute(q)

    lst = []
    for row in c:
        if row[0] == 0:
            continue
        if row['str'].startswith('cmpxchg'):
            lst.append(MtraceLock(row[0], row[1], row[2], dbFile, dataName, model.MtraceCmpxchgSample))
        else:
            lst.append(MtraceLock(row[0], row[1], row[2], dbFile, dataName, model.MtraceLockSample))
    conn.close()
    return lst
