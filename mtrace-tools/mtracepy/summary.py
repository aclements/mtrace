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
        self.spinTime = row['spin_cycles'] + (row['spin_locked_accesses'] + row['spin_traffic_accesses']) * model.MISS_LATENCY
        self.numCpus = row['num_cpus']
        self.numRam = row['num_ram']
        offsetSum = ((row['traffic_accesses'] + row['locked_accesses']) * model.MISS_LATENCY) + (row['lock_acquires'] * model.LOCK_LATENCY)
        self.numOps = row['num_ops']

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
