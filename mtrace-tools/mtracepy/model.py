import copy
import sqlite3

MISS_LATENCY = 200
LOCK_LATENCY = 500
ICNT_CONTENTION = 50

def get_traffic_latency(numCores = 0):
    return MISS_LATENCY + (numCores * ICNT_CONTENTION)

def get_locked_latency(numCores = 0):
    return get_traffic_latency(numCores)

def get_lock_latency(numCores = 0):
    if numCores == 0:
        raise Exception('foo')
    return LOCK_LATENCY * numCores

class MtraceLockSample(object):
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

    def time(self, numCores = 0):
        return (self.cycles +
                (self.num * get_lock_latency(numCores)) +
                (self.lockedAccesses * get_locked_latency(numCores)) + 
                (self.trafficAccesses * get_traffic_latency(numCores)))

    def copy(self):
        return copy.copy(self)

    def __str__(self):
        return '%lu %lu %lu %u' % (self.cycles, self.lockedAccesses, self.trafficAccesses, self.num)

class MtraceAccessSample(object):
    def __init__(self, traffic, locked, num = 1):
        self.traffic = traffic
        self.locked = locked
        self.num = num

    def add(self, aggregate):
        self.traffic += aggregate.traffic
        self.locked += aggregate.locked
        self.num += aggregate.num

    def time(self, numCores = 0):
        return ((self.traffic * get_traffic_latency(numCores)) + 
                (self.locked * get_locked_latency(numCores)))

    def copy(self):
        return copy.copy(self)

    def __str__(self):
        return '%lu %lu %lu %u' % (self.traffic, self.locked, self.num)

class MtraceSummary(object):

    def __init__(self, dbFile, dataName):
        conn = sqlite3.connect(dbFile)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
    
        q = '''SELECT start_ts, end_ts, spin_locked_accesses, 
               spin_traffic_accesses, spin_cycles,
               num_cpus, num_ram, locked_accesses, 
               traffic_accesses, locked_accesses, num_ops, 
               lock_acquires FROM %s_summary'''
        q = q % (dataName)
        c.execute(q)

        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (q, len(rs)))
        row = rs[0]
 
        self.startTs = row['start_ts']
        self.endTs = row['end_ts']
        self.spinCycles = row['spin_cycles']
        self.spinTrafficAccesses = row['spin_traffic_accesses']
        self.spinLockedAccesses = row['spin_locked_accesses']
        self.trafficAccesses = row['traffic_accesses']
        self.lockedAccesses = row['locked_accesses']
        self.lockAcquires = row['lock_acquires']

    def get_max_work(self, numCores = 0):
        return (self.get_min_work(numCores) + 
                ((self.trafficAccesses - self.spinTrafficAccesses) * get_traffic_latency(numCores)) + 
                ((self.lockedAccesses - self.spinLockedAccesses) * get_locked_latency(numCores)) +
                (self.lockAcquires * get_lock_latency(numCores)))

    def get_min_work(self, numCores = 0):
        return self.endTs - self.startTs - self.spinCycles

    def __str__(self):
        s = ''
        s += '  %-16s %lu\n' % ('cycles', self.endTs - self.startTs)
        s += '  %-16s %lu\n' % ('spin', self.spinTime)
        s += '  %-16s %lu\n' % ('min work', self.minWork)
        s += '  %-16s %lu\n' % ('max work', self.maxWork)
        s += '  %-16s %lu\n' % ('num ops', self.numOps)
        s += '  %-16s %lu\n' % ('num cpus', self.numCpus)
        s += '  %-16s %lu' % ('num ram', self.numRam)
        return s
