import sqlite3
from util import uhex

class MtraceSerialSection:
    
    def __init__(self, serialId, startTs, endTs, tid):
        self.serialId = serialId
        self.startTs = startTs
        self.endTs = endTs
        self.tid = tid

    def __str__(self):
        return '%lu -- [%lu, %lu]' % (self.tid, self.startTs, self.endTs)

    def get_time(self):
        return self.endTs - self.startTs

class MtraceLock:
    
    def __init__(self, labelType, labelId, lock, db, dataName):
        self.labelType = labelType
        self.labelId = labelId
        self.lock = lock
        self.db = db
        self.dataName = dataName

        self.sections = None
        self.name = None
        self.holdTime = None
        self.inited = False

    def __str__(self):
        return '%s:%lu:%lx' % (self.get_name(), self.labelId, uhex(self.lock))

    def __init_state(self):
        if self.inited:
            return
        c = self.db.cursor()

        # Sections
        q = 'SELECT id, start_ts, end_ts, tid FROM %s_locked_sections where ' + \
            'label_id = %lu'
        q = q % (self.dataName,
                 self.labelId)
        c.execute(q)
        self.sections = []
        self.holdTime = 0
        for row in c:
            section = MtraceSerialSection(row[0], row[1], row[2], row[3])
            self.sections.append(section)
            self.holdTime += section.endTs - section.startTs

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

        self.inited = True

    def get_sections(self):
        self.__init_state()
        return self.sections
    def get_hold_time(self):
        self.__init_state()
        return self.holdTime
    def get_name(self):
        self.__init_state()
        return self.name

def get_locks(dbFile, dataName):
    conn = sqlite3.connect(dbFile)
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
