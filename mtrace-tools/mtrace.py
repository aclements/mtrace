import sqlite3

class MtraceDB:
    def __init__(self, dbFile):
        self.dbFile = dbFile
        self.conn = sqlite3.connect(self.dbFile)

    def exec_single(self, query):
        c = self.conn.cursor()
        c.execute(query)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        r = rs[0]
        c.close()
        return r
