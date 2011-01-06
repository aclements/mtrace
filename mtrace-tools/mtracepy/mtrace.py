from columns import ColumnValue, Address, Unsigned, AccessType, create_column_string, create_column_objects, get_column_object
from util import uhex
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

class MtraceCallInterval:
    def __init__(self, pc):
        self.pc = pc

    def __str__(self):
        return '%lx' % uhex(self.pc)

class MtraceBacktracer:
    def __init__(self, dbFile, dataName, accessId):
        self.mtraceDB = MtraceDB(dbFile)
        self.dataName = dataName
        self.accessId = accessId

        self.topId = None
        self.frames = None

    def __get_return_interval(self, topId):
        q = 'SELECT ret_id, end_pc FROM %s_call_intervals WHERE id = %lu'
        q = q % (self.dataName,
                 topId)
        return self.mtraceDB.exec_single(q)

    def __walk_call_stack(self, topId):
        if topId == 0:
            return

        r = self.__get_return_interval(topId)
        retId = r[0]
        pc = r[1]

        self.frames.append(MtraceCallInterval(pc))

        if retId != 0:
            self.__walk_call_stack(retId)

    def __build_frames(self):
        q = 'SELECT cpu, pc FROM %s_accesses WHERE access_id = %u'
        q = q % (self.dataName,
                 self.accessId)

        r = self.mtraceDB.exec_single(q)
        cpu = r[0]
        pc = r[1]
        
        self.frames = []
        # Save the top frame
        self.frames.append(MtraceCallInterval(pc))

        q = 'SELECT id FROM %s_call_intervals WHERE cpu = %u AND ' + \
            'access_start < %lu AND %lu <= access_end'
        q = q % (self.dataName,
                 cpu,
                 self.accessId,
                 self.accessId)

        topId = self.mtraceDB.exec_single(q)[0]
        # Skip the top interval, which we already accounted for
        nextId = self.__get_return_interval(topId)[0]

        self.__walk_call_stack(nextId)

    def get_depth(self):
        if self.frames == None:
            self.__build_frames()

        return len(self.frames)

    def get_interval(self, i):
        if self.frames == None:
            self.__build_frames()

        return self.frames[i]

    class Iter:
        def __init__(self, bt):
            self.i = 0
            self.bt = bt

        def __iter__(self):
            return self

        def next(self):
            if self.bt.get_depth() == self.i:
                raise StopIteration()
            interval = self.bt.get_interval(self.i)
            self.i += 1
            return interval

    def __iter__(self):
        return MtraceBacktracer.Iter(self)

class MtraceAccess:
    columns = [ 
                ColumnValue(Unsigned.create, 'access_id'),
                ColumnValue(AccessType.create, 'access_type'),
                ColumnValue(Address.create, 'pc'),
                ColumnValue(Address.create, 'guest_addr') 
              ]

    def __init__(self, dbFile, dataName, accessId):
        self.dbFile = dbFile
        self.dataName = dataName
        self.accessId = accessId
        self.values = None

    def __build_values(self):
        select = create_column_string(MtraceAccess.columns)
        q = 'SELECT ' + select + ' FROM %s_accesses WHERE access_id = %lu;'
        q = q % (self.dataName,
                 self.accessId)
        row = MtraceDB(self.dbFile).exec_single(q)
        self.values = create_column_objects(MtraceAccess.columns, row)

    def __str__(self):
        if self.values == None:
            self.__build_values()
        s = '[ ' + str(self.values[0])
        for val in self.values[1:]:
            s += ', ' + str(val)
        s += ' ]'
        return s

    def get_values(self):
        if self.values == None:
            self.__build_values()
        return self.values

    def get_value(self, column):
        return get_column_object(self.get_values(), column)

class MtraceInstanceDetail:
    def __init__(self, dbFile, dataName, labelId):
        self.dbFile = dbFile
        self.dataName = dataName
        self.labelId = labelId
        self.accesses = None

    def __build_accesses(self):
        q = 'SELECT access_id FROM %s_accesses WHERE label_id = %lu;'
        q = q % (self.dataName,
                 self.labelId)

        conn = sqlite3.connect(self.dbFile)
        c = conn.cursor()
        c.execute(q)

        self.accesses = []
        for row in c:
            self.accesses.append(MtraceAccess(self.dbFile, self.dataName, row[0]))
            
        c.close()

    def get_access_num(self):
        if self.accesses == None:
            self.__build_accesses()
        return len(self.accesses)

    def get_access(self, i):
        if self.accesses == None:
            self.__build_accesses()
        return self.accesses[i]

    class Iter:
        def __init__(self, detail):
            self.i = 0
            self.detail = detail

        def __iter__(self):
            return self

        def next(self):
            if self.detail.get_access_num() == self.i:
                raise StopIteration()
            access = self.detail.get_access(self.i)
            self.i += 1
            return access

    def __iter__(self):
        return MtraceInstanceDetail.Iter(self)
