import sqlite3
import hashlib
import sys

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

def checksum(fileName, maxBytes = sys.maxint):
    f = open(fileName,"rb")
    m = hashlib.md5()
    while True:
        bc = min(maxBytes, 256)
        bytes = f.read(bc)
        if bytes == '':
            break
        m.update(bytes)
        maxBytes -= bc
        if maxBytes == 0:
            break
    f.close()
    return m.digest()

def apply_filters(lst, filters):
    if len(filters) > 0:
        lst2 = []
        for e in lst:
            lst2.append(e)
            for f in filters:
                if f.filter(e) == False:
                    lst2.pop()
                    break
        return lst2
    else:
        return lst

class MtraceDB:
    def __init__(self, dbFile):
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
