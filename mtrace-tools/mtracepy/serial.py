import os
import errno
import lock
import harcrit
import util
import cPickle

class MtraceSerials(object):
    def __init__(self, dbFile, dataName):
        self.dataName = dataName
        self.dbFile = dbFile
        self.csum = None
        self.pickleOk = False

        self.serials = lock.get_locks(dbFile, dataName)
        self.serials.extend(harcrit.get_harcrits(dbFile, dataName));

    def filter(self, filters, persist=False, removed=None):
        filtered = util.apply_filters(self.serials, filters, removed=removed)
        if persist:
            self.serials = filtered
        return filtered

    def close(self, pickleDir):
        if self.csum == None:
            self.csum = util.checksum(self.dbFile)
        if self.pickleOk:
            return

        base, ext = os.path.splitext(self.dbFile)
        base = os.path.basename(base)
        picklePath = pickleDir + '/' + base + '-' + self.dataName + '.pkl'
       
        output = open(picklePath, 'wb')
        cPickle.dump(self, output)
        output.close()

    @staticmethod
    def open(dbFile, dataName, pickleDir):
        base, ext = os.path.splitext(dbFile)
        base = os.path.basename(base)
        picklePath = pickleDir + '/' + base + '-' + dataName + '.pkl'

        serials = None
        try:
            pickleFile = open(picklePath, 'r')
            serials = cPickle.load(pickleFile)

            if serials.dataName != dataName:
                raise Exception('unexpected dataName')
            if serials.csum != util.checksum(dbFile):
                raise Exception('checksum mismatch: stale pickle?')

            # This following members are ephemeral
            serials.dbFile = dbFile
            serials.pickleOk = True

            pickleFile.close()
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            serials = MtraceSerials(dbFile, dataName)
        
        return serials
