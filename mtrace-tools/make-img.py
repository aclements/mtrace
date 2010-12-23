#!/usr/bin/python

#
# Run make-img.py with no arguments for usage
#

import sys
import os.path
import subprocess
import signal
import shutil
import traceback

default_img_size = '300M'
default_includes = 'python,makedev'

mosbench_includes = 'make,rsync,dropbear,libpcre3,numactl,procps,sudo,ifupdown,netbase'

# colors differentiate subprocess output from make-img.py
text_log_color   = '\033[95m'       # purplish
text_err_color   = '\033[91m'       # redish
text_end_color   = '\033[0m' 

def print_log(string):
    print text_log_color + string + text_end_color

def print_err(string):
    print text_err_color + string + text_end_color

class CopyCmd:
    # (relative path to script location, absolute path in disk image)
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

        if self.src.startswith('/') == False:
            self.src = sys.path[0] + '/' + self.src
        if self.dst.startswith('/') == False:
            self.src = sys.path[0] + '/' + self.src

    def run(self, img):
        src = self.src
        chroot_dst = self.dst
        chroot_src = '/tmp/' + os.path.basename(self.src)
        # Copy once, chroot, and move to avoid accidentally overwriting
        # the host system files
        sudo(['cp', '-r', src, img.tmp + '/tmp']).run()
        img.chroot(['sh', '-c', 'mv ' + chroot_src + ' ' + chroot_dst ]).run()

class FixupCmd:
    # chroot into the disk image and run cmd shell command
    def __init__(self, cmd):
        self.cmd = cmd

    def run(self, img):
        img.chroot(['sh', '-c', self.cmd]).run()

default_cmds = [ 
                 CopyCmd('img-files/shadow', '/etc/shadow'),
                 CopyCmd('img-files/inittab', '/etc/inittab'),
                 CopyCmd('img-files/run-cmdline', '/etc/init.d/run-cmdline'),
                 CopyCmd('img-files/run-cmdline.py', '/usr/bin/run-cmdline.py'),
                 CopyCmd('img-files/interfaces', '/etc/network/interfaces'),
                 FixupCmd('cd /dev && /sbin/MAKEDEV ttyS'),
                 FixupCmd('cd /etc/init.d && update-rc.d run-cmdline defaults')
               ]

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

    def bootstrap(self, include):
        self.mount()
        sudo(['debootstrap',
              '--arch',
              'amd64',
              '--include=' + include,
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

    def run_cmds(self, cmds):
        self.mount()
        for cmd in cmds:
            cmd.run(self)
        self.umount()

def usage():
    print """Usage: make-img.py output-file [ -size size -fixup fixup -copy src,dst 
                      -include pkg0,pkg1,... -mosbench mosbenchsrc ]

    'size' is the disk image size in kilobytes. Optional suffixes
      'M' (megabyte, 1024 * 1024) and 'G' (gigabyte, 1024 * 1024 * 1024) are
      supported any 'k' or 'K' is ignored

    'fixup' is a string of shell command to execute while chrooted into the
      disk image

    'src,dst' is a source file on the host file system to copy to the 
      destination on the disk image

    'pkg0,pkg1,...' is a comma separated list of Debian package names

    'mosbenchsrc' is the path to your mosbench source tree
"""
    exit(1)

def parse_args(argv):
    if len(argv) < 2:
        usage()

    def size_handler(val):
        global default_img_size
        default_img_size = val

    def fixup_handler(val):
        global default_cmds
        default_cmds.append(FixupCmd(val))

    def include_handler(val):
        global default_includes
        default_includes = default_includes + ',' + val

    def copy_handler(val):
        global default_cmds
        split = val.partition(',')
        default_cmds.append(CopyCmd(split[0], split[2]))

    def mosbench_handler(val):
        global mosbench_includes

        # Copy the mosbench tree to the same absolute path in the image
        src = val
        chroot_dst = os.path.abspath(val)
        chroot_dir = os.path.dirname(chroot_dst)
        fixup_handler('mkdir -p ' + chroot_dir)
        copy_handler(src + ',' + chroot_dst)

        include_handler(mosbench_includes)
        copy_handler('/etc/hosts,/etc/hosts')

    handler = {
        '-size': size_handler,
        '-fixup': fixup_handler,
        '-copy': copy_handler,
        '-include': include_handler,
        '-mosbench': mosbench_handler
    }

    args = argv[2:]
    for i in range(0, len(args), 2):
        handler[args[i]](args[i + 1])
    
def main(argv=None):
    if argv is None:
        argv = sys.argv
    
    parse_args(argv)
    img = DiskImage(argv[1])

    def on_sigint(signum, frame):
        img.cleanup()
    signal.signal(signal.SIGINT, on_sigint)

    try:
        img.create(default_img_size)
        img.format()
        img.bootstrap(default_includes)
        img.run_cmds(default_cmds)
    except Exception as ex:
        print_err('\n[failed]')
        traceback.print_exc(file=sys.stdout)

    img.cleanup()
    exit(0)

if __name__ == "__main__":
    sys.exit(main())
