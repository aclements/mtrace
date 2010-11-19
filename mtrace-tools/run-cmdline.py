#!/usr/bin/python
#
# * Put this script in /usr/bin/
# * Put run-cmdline in /etc/init.d/
# * Add a symlink to run run-cmdline at boot:
#    cd /etc/inid.d && update-rc.d run-cmdline defaults

# XXX port this to sh (i.e. run-cmdline)

import shlex
import subprocess
import os
import re
import sys
import time

for arg in sys.argv[1:]: 
    time.sleep(int(arg));

f = open('/proc/cmdline', 'r')
cmdline = f.readline()

for m in re.finditer('run-cmdline="(.*?)"\s*', cmdline):
    cmd = m.group(1)
    args = shlex.split(cmd)

    try:
        print 'Running %s ...' % cmd
        p = subprocess.Popen(args)
        p.wait()
        if p.returncode:
            print 'Command "%s" failed: %d' % (cmd, p.returncode)
    except OSError, e:
        print 'Failed to run command "%s" failed: %s' % (cmd, os.strerror(e.errno))
