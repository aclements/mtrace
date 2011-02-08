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

class MtraceSerialAggregate:
    def __init__(self, cycles, lockedAccesses, trafficAccesses, num = 1):
        self.cycles = cycles
        self.lockedAccesses = lockedAccesses
        self.trafficAccesses = trafficAccesses
        self.num = num

    def add(self, aggregate):
        self.cycles += aggregate.cycles
        self.lockedAccesses += aggregate.lockedAccesses
        self.trafficAccesses += aggregate.trafficAccesses
        self.num += aggregate.num

    def time(self):
        return (self.cycles +
                (self.num * model.LOCK_LATENCY) +
                (self.lockedAccesses * model.MISS_LATENCY) + 
                (self.trafficAccesses * model.MISS_LATENCY))

    def copy(self):
        return copy.copy(self)

    def __str__(self):
        return '%lu %lu %lu %u' % (self.cycles, self.lockedAccesses, self.trafficAccesses, self.num)

class MtraceLock:
    
    def __init__(self, labelType, labelId, lock, db, dataName):
        self.labelType = labelType
        self.labelId = labelId
        self.lock = lock
        self.db = db
        self.dataName = dataName

        self.exclusive = None
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
        self.holdTime = 0
        self.exclusive = MtraceSerialAggregate(0, 0, 0, num = 0)

        self.holdTime = 0

        # Sections
        q = '''SELECT id, start_ts, end_ts, start_cpu, read, tid, pc, str, 
               locked_accesses, traffic_accesses FROM %s_locked_sections 
               WHERE label_id = %lu and lock = %lu and read <> 1'''
        q = q % (self.dataName,
                 self.labelId,
                 self.lock)
        c = self.db.cursor()
        c.execute(q)
        for row in c:
            if row[4] >= 1:
                continue

            section = MtraceSerialSection(row['id'], row['start_ts'], row['end_ts'], 
                                          row['start_cpu'], row['read'], row['tid'], row['pc'])

            agg = MtraceSerialAggregate(section.endTs - section.startTs,
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

        # Name (label str and lock str)
        q = '''SELECT str FROM %s_locked_sections WHERE label_id = %lu and lock = %lu LIMIT 1'''
        q = q % (self.dataName,
                 self.labelId,
                 self.lock)
        c = self.db.cursor()
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

def get_locks(dbFile, dataName):
    conn = sqlite3.connect(dbFile)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    q = 'SELECT DISTINCT label_type, label_id, lock FROM %s_locked_sections'
    q = q % (dataName)
    c.execute(q)

    lst = []
    for row in c:
        if row[0] == 0:
            continue
        lst.append(MtraceLock(row[0], row[1], row[2], conn, dataName))
    return lst
