mtrace_label_heap       = 1
mtrace_label_block      = 2
mtrace_label_static     = 3
mtrace_label_percpu     = 4

mtrace_label_str        =  { mtrace_label_heap   : 'heap',
                             mtrace_label_block  : 'block',
                             mtrace_label_static : 'static',
                             mtrace_label_percpu : 'percpu' }

# XXX there must be a better way..
def uhex(i):
    return (i & 0xffffffffffffffff)

class SelectRow:
    def __init__(cols, row):
        pass

class MtraceDB:
    def __init__(self, dbFile, dataName = None):
        self.dbFile = dbFile
        self.conn = sqlite3.connect(self.dbFile)
        self.dataName = dataName

    def exec_single(self, query):
        c = self.conn.cursor()
        c.execute(query)
        rs = c.fetchall()
        if len(rs) != 1:
            raise Exception('%s returned %u rows' % (query, len(rs)))
        r = rs[0]
        c.close()
        return r

    def select(self, table, cols, where):
        selectCols = cols[0]
        for col in cols[1:]:
            selectCols += ', ' + col
        q = 'SELECT %s FROM %s_%s WHERE %s' % (selectCols,
                                               self.dataName,
                                               self.table,
                                               where)
        print q
        exit(1)
