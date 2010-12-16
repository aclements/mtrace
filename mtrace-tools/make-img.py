#!/usr/bin/python

import sys
import os.path
import subprocess
import signal
import shutil
import traceback

default_img_size = '300M'

# (relative path to script location, absolute path in disk image)
extra_files      = [ 
                     ( 'img-files/shadow', '/etc/shadow' ),
                     ( 'img-files/inittab', '/etc/inittab' ),
                     ( 'img-files/run-cmdline', '/etc/init.d/run-cmdline' ),
                     ( 'img-files/run-cmdline.py', '/usr/bin/run-cmdline.py' )
                   ]

# chroot into the disk image and run these shell commands
fixup_cmds       = [ 
                     'cd /dev && /sbin/MAKEDEV ttyS',
                     'cd /etc/init.d && update-rc.d run-cmdline defaults',
                   ]

# colors differentiate subprocess output from make-img.py
text_log_color   = '\033[95m'       # purplish
text_err_color   = '\033[91m'       # redish
text_end_color   = '\033[0m' 

def print_log(string):
    print text_log_color + string + text_end_color

def print_err(string):
    print text_err_color + string + text_end_color

class ProcessHelper:
    def __init__(self, args):
        self.args = args

    def run(self, quiet = False):
        s = self.args[0]
        for a in self.args[1:]:
            s = s + ' ' + a

        if quiet:
            f = open('/dev/null', 'r+')
            p = subprocess.Popen(self.args, stdout = f, stderr = f)
            p.wait()
            return

        print_log('[running]  ' + s)
        p = subprocess.Popen(self.args)
        self.process = p
        p.wait()
        if p.returncode:
            raise Exception('Failed: %s returned %u' % (s, p.returncode))

        #print_log('[complete] ' + s)

def sudo(args):
    args.insert(0, 'sudo')
    return ProcessHelper(args)

class DiskImage:
    def __init__(self, filepath):
        self.filepath = filepath
        self.tmp = 'tmp.%u' % os.getpid()

    def chroot(self, args):
        args.insert(0, self.tmp)
        args.insert(0, 'chroot')
        return sudo(args)

    def mount(self, quiet = False):
        if os.path.exists(self.tmp):
            raise Exception('Failed: temporary directory exists: %s' % self.tmp)               
        else:
            os.mkdir(self.tmp)

        sudo(['mount',
              '-o',
              'loop',
              self.filepath,
              self.tmp]).run(quiet)

    def umount(self, quiet = False):
        sudo(['umount',
              self.tmp]).run(quiet)
        os.rmdir(self.tmp)

    def create(self, img_size):
        if os.path.isfile(self.filepath):
            raise Exception('Failed: File \'%s\' exists' % self.filepath)
        ProcessHelper(['qemu-img', 
                       'create', 
                       self.filepath,
                       img_size]).run()

    def format(self):
        ProcessHelper(['/sbin/mkfs.ext3', 
                       '-F', 
                       self.filepath]).run()

    def bootstrap(self):
        self.mount()
        sudo(['debootstrap',
              '--arch',
              'amd64',
              '--include=python',
              '--include=makedev',
              '--exclude=udev',
              '--variant=minbase',
              'squeeze',
              self.tmp,
              'http://ftp.debian.org/debian/']).run()
        self.umount()

    def cleanup(self):
        try:
            self.umount(True)
        except:
            pass
        
        try:
            os.rmdir(self.tmp)
        except:
            pass

    def copy_files(self, files):
        self.mount()
        for pair in files:
            src = sys.path[0] + '/' + pair[0]
            dst = self.tmp + pair[1]
            sudo(['cp', src, dst]).run()
        self.umount()

    def fixup(self, cmds):
        self.mount()
        for cmd in cmds:
            self.chroot(['sh', '-c', cmd]).run()
        self.umount()

def main(argv=None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 2:
        print 'usage: ' + argv[0] + ' output-file'
        exit(1)

    img_size = default_img_size

    img = DiskImage(argv[1])

    def on_sigint(signum, frame):
        img.cleanup()
    signal.signal(signal.SIGINT, on_sigint)

    try:
        img.create(img_size)
        img.format()
        img.bootstrap()
        #img.copy_files(extra_files)
        #img.fixup(fixup_cmds)
    except Exception as ex:
        print_err('\n[failed]')
        traceback.print_exc(file=sys.stdout)

    img.cleanup()
    exit(0)

if __name__ == "__main__":
    sys.exit(main())
