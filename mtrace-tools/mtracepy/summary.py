import sqlite3

class MtraceSummary:

    def __init__(self, dbFile, dataName):
        self.startTs = None
        self.endTs = None
        self.missDelay = None
        self.numCpus = None
        self.numRam = None
        self.tsOffset = None
        self.numOps = None
        self.minWork = None
        self.maxWork = None

        conn = sqlite3.connect(dbFile)
        c = conn.cursor()
    
        q = '''SELECT start_ts, end_ts, spin_time, miss_delay, 
               num_cpus, num_ram, cpu0_ts_offset, cpu1_ts_offset, 
               cpu2_ts_offset, cpu3_ts_offset, num_ops FROM %s_summary'''
        q = q % (dataName)
        c.execute(q)

        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (q, len(rs)))
        row = rs[0]
        
        self.startTs = row[0]
        self.endTs = row[1]
        self.spinTime = row[2]
        self.missDelay = row[3]
        self.numCpus = row[4]
        self.numRam = row[5]
        self.tscOffset = []
        offsetSum = 0;
        for offset in row[6:10]:
            self.tscOffset.append(offset)
            offsetSum += offset
        self.numOps = row[10]

        self.minWork = self.endTs - self.startTs - self.spinTime
        self.maxWork = self.minWork + offsetSum

    def __str__(self):
        s = ''
        s += '  %-16s %lu\n' % ('cycles', self.endTs - self.startTs)
        s += '  %-16s %lu\n' % ('spin', self.spinTime)
        s += '  %-16s %lu\n' % ('min work', self.minWork)
        s += '  %-16s %lu\n' % ('max work', self.maxWork)
        s += '  %-16s %lu\n' % ('miss delay', self.missDelay)
        i = 0
        for offset in self.tscOffset:
            s += '  %-16s %lu\n' % ('%u tsc offset' % i, offset)
            i += 1
        s += '  %-16s %lu\n' % ('num ops', self.numOps)
        s += '  %-16s %lu\n' % ('num cpus', self.numCpus)
        s += '  %-16s %lu' % ('num ram', self.numRam)
        return s
