import sqlite3
import model

class MtraceSummary:

    def __init__(self, dbFile, dataName):
        self.startTs = None
        self.endTs = None
        self.numCpus = None
        self.numRam = None
        self.tsOffset = None
        self.numOps = None
        self.minWork = None
        self.maxWork = None

        conn = sqlite3.connect(dbFile)
        c = conn.cursor()
    
        q = '''SELECT start_ts, end_ts, spin_locked_accesses, spin_locked_accesses, 
               num_cpus, num_ram, locked_accesses, traffic_accesses, 
               locked_accesses, traffic_accesses, num_ops, spin_traffic_accesses, spin_cycles, lock_acquires FROM %s_summary'''
        q = q % (dataName)
        c.execute(q)

        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (q, len(rs)))
        row = rs[0]
        
        self.startTs = row[0]
        self.endTs = row[1]
        self.spinTime = row[12] + (row[2] + row[11]) * model.MISS_LATENCY
        self.numCpus = row[4]
        self.numRam = row[5]
        offsetSum = ((row[6] + row[7]) * model.MISS_LATENCY) + (row[11] * model.LOCK_LATENCY)
        self.numOps = row[10]

        self.minWork = self.endTs - self.startTs - self.spinTime
        self.maxWork = self.minWork + offsetSum

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
