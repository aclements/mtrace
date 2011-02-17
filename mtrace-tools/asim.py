#!/usr/bin/python

import sys
import copy
import random

DEBUG = False

class Section:
    def __init__(self, key, critical, length):
        self.key = key
        self.critical = critical
        self.length = length

    def subtract(self, amount):
        self.length -= amount

    def copy(self):
        return copy.copy(self)

    def __str__(self):
        return '%u: %u' % (self.key, self.length)

class Timeline:
    def __init__(self, core):
        self.core = core
        self.timeline = []
        self.work = 0
        self.nextSection = None

    def append(self, section):
        self.timeline.append(section)
        self.work += section.length

    def empty(self):
        return len(self.timeline) == 0

    def get_random_section(self):
        if self.nextSection:
            section = self.nextSection
            self.nextSection = None
            return section

        if DEBUG:
            for section in self.timeline:
                print section,
            print ''

        r = random.randint(0, self.work - 1)        
        for section in self.timeline:
            if r < section.length:
                return section
            r -= section.length
        raise Exception('get_random_section')

    def set_next_section(self, section):
        self.nextSection = section

    def subtract_section(self, section, amount):
        section.subtract(amount)
        if section.length == 0:
            self.timeline.remove(section)
        self.work -= amount

    def __str__(self):
        s = self.timeline[0].__str__()
        for section in self.timeline[:1]:
            s += ' ' + section.__str__()
        return s

TIMELINE = [ Section(1, False, 900), Section(2, True, 10) ]
PERCORE_TIMELINE = None

def do_one(numCores):
    PERCORE_TIMELINE = []
    for i in range(0, numCores):
        timeline = Timeline(i)
        for section in TIMELINE:
            timeline.append(section.copy())
        PERCORE_TIMELINE.append(timeline)

    time = 0
    while True:
        allDone = True
        keys = {}
        
        for timeline in PERCORE_TIMELINE:
            if timeline.empty() == False:
                allDone = False
                section = timeline.get_random_section()
                if section.key in keys:
                    timeline.set_next_section(section)
                else:
                    timeline.subtract_section(section, 1)
                    if section.critical:
                        keys[section.key] = 1
        if allDone:
            break
        time += 1

    return float(time) / numCores
    

def usage():
    print """Usage: asim.py DB-file name"""
    exit(1)

def main(argv = None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 3:
        usage()

        
    oneTp = do_one(1)
    #print '%u\t%.2f\t%.2f' % (1, oneTp, oneTp / oneTp)
    print '%u\t%.2f' % (1, oneTp / oneTp)
    for n in range(2, 50):
        tp = do_one(n)
        speedUp = oneTp / tp
        print '%u\t%.2f' % (n, speedUp)
        #print '%u\t%.2f\t%.2f' % (n, tp, speedUp)

if __name__ == "__main__":
    sys.exit(main())
