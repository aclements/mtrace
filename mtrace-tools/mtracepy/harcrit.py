import sqlite3
import summary
import lock
from util import uhex
import model
import copy

class MtraceHarcrit:

    def __init__(self, labelType, labelId, dbFile, dataName, missDelay):
        self.labelType = labelType
        self.labelId = labelId
        self.dbFile = dbFile
        self.dataName = dataName
        self.missDelay = missDelay

        self.lock = 0

        self.exclusive = None
        self.kerncalls = None
        self.name = None
        self.tids = None
        self.cpus = None
        self.pcs = None
        self.inited = False

    def __init_state(self):
        if self.inited:
            return

        conn = sqlite3.connect(self.dbFile)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        self.cpus = {}
        self.tids = {}
        self.pcs = {}
        self.kerncalls = {}
        self.exclusive = model.MtraceAccessSample(0, 0, num = 0)

        q = 'SELECT access_id, tid, cpu, pc, call_trace_tag from %s_accesses WHERE label_id = %lu AND locked_id = 0'
        q = q % (self.dataName, self.labelId)
        c.execute(q)
        for row in c:
            section = lock.MtraceSerialSection(row[0], 0, self.missDelay, 
                                               row[2], 0, row[1], row[3])
            agg = model.MtraceAccessSample(1, 0)

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

            if row['call_trace_tag'] in self.kerncalls:
                self.kerncalls[row['call_trace_tag']].add(agg)
            else:
                self.kerncalls[row['call_trace_tag']] = agg.copy()
        
        # Name
        q = 'SELECT str FROM %s_labels%u WHERE label_id = %lu'
        q = q % (self.dataName,
                 self.labelType,
                 self.labelId)
        c.execute(q)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        self.name = rs[0][0]

        conn.close()
        self.inited = True

    def get_exclusive_stats(self):
        self.__init_state()
        return self.exclusive
    def get_name(self):
        self.__init_state()
        return self.name
    def get_label_id(self):
        return self.labelId
    def get_tids(self):
        self.__init_state()
        return self.tids
    def get_cpus(self):
        self.__init_state()
        return self.cpus
    def get_lock(self):
        self.__init_state()
        return self.lock
    def get_pcs(self):
        self.__init_state()
        return self.pcs
    def get_kerncalls(self):
        self.__init_state()
        return self.kerncalls

def get_harcrits(dbFile, dataName):
    conn = sqlite3.connect(dbFile)
    c = conn.cursor()

    q = 'SELECT DISTINCT label_type, label_id FROM %s_accesses WHERE locked_id = 0;'
    q = q % (dataName)
    c.execute(q)

    lst = []
    for row in c:
        if row[0] == 0:
            continue
        lst.append(MtraceHarcrit(row[0], row[1], dbFile, dataName, model.MISS_LATENCY))
    conn.close()
    return lst
