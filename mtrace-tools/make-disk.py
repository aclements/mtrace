#!/usr/bin/python

import sys
import os.path

class DiskImage:
    def __init__(self, filepath):
        if os.path.isfile(filepath):
            raise Exception('File %s exists' % filepath)

def main(argv=None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 2:
        print 'usage: ' + argv[0] + ' output-file'
        exit(1)

    try:
        img = DiskImage(argv[1])
    except Exception as ex:
        print ex

    exit(0)

if __name__ == "__main__":
    sys.exit(main())
