#!/usr/bin/python

import sys
import random

LOCK_COUNT  = 0
LOCK_HOLDER = {}

class Work(object):
    def __init__(self, serial, length):
        global LOCK_COUNT
        self.serial = serial
        self.length = length
        self.lock = LOCK_COUNT + 1
        LOCK_COUNT = LOCK_COUNT + 1
        LOCK_HOLDER[self.lock] = None

    def lock_holder(self):
        return LOCK_HOLDER[self.lock]

    def acquire(self, holder):
        if LOCK_HOLDER[self.lock] and LOCK_HOLDER[self.lock] != holder:
            raise Exception('oops')
        LOCK_HOLDER[self.lock] = holder

    def release(self):
        LOCK_HOLDER[self.lock] = None

class WorkQueue(object):
    def __init__(self, workLoad):
        self.workDone = 0
        self.totalWork = 0
        self.workLoad = []
        for work in workLoad:
            self.workLoad.append(work)
            self.totalWork += work.length
        self.currentWork = None
        self.restart()

    def restart(self):
        if self.currentWork and self.currentWork.serial:
            self.currentWork.release()
        self.currentWork = None
        self.index = random.randint(0, self.totalWork - 1)
        self.__update_current_work()

    def __update_current_work(self):
        i = self.index
        for work in self.workLoad:
            if i < work.length:
                self.currentWork = work
                return
            i -= work.length
        raise Exception('oops')

    def execute(self):
        w = self.currentWork            
        self.__update_current_work()
        if w != self.currentWork:
            if w.serial:
                w.release()
            w = self.currentWork

        if w.serial:
            holder = w.lock_holder()
            if holder != None and holder != self:
                return False
            w.acquire(self)

        self.workDone += 1
        self.index = (self.index + 1) % self.totalWork
        return True


def sim(numCores):
    workQueue = [ WorkQueue(WORKLOAD) for x in range(0, numCores) ]
    cycles = 0
    while True:
        for i in range (0, numCores):
            if workQueue[i].execute():
                if (workQueue[i].workDone % workQueue[i].totalWork) == 0:
                    workQueue[i].restart()

        cycles += 1
        if cycles >= SIM_CYCLES:
            break

    for work in WORKLOAD:
        work.release()

    totalWorkDone = 0
    for i in range (0, numCores):
        totalWorkDone += workQueue[i].workDone
    return float(totalWorkDone) / float(SIM_CYCLES)


START_CORE = 1
STOP_CORE  = 128
SIM_CYCLES = 10000
#WORKLOAD   = [ Work(False, 90), Work(True, 10) ]
#WORKLOAD   = [ Work(False, 50), Work(True, 10), Work(True, 10), Work(True, 10), Work(True, 10), Work(True, 10) ]
WORKLOAD   = [ Work(False, 50), Work(True, 50) ]

for i in range(START_CORE, STOP_CORE + 1):
    tp = sim(i)
    print '%u\t%f' % (i, tp)
