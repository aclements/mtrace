#!/bin/sh

# Add/remove commands here
cmds='run-cmdline="/root/fops-dir 1 2 /root/foo 1" '
#cmds=$cmds'run-cmdline="/root/proc-ping-pong 0 1 1" '
cmds=$cmds'run-cmdline="shutdown -h now"'

QEMU=/usr/local/qemu-mtrace/bin/qemu-system-x86_64
DISK=disk.img
KERN=bzImage
OUT=/tmp/`whoami`-mtrace.out

echo "***"
echo "*** Writing mtrace to $OUT"
echo "***"

$QEMU                                                                   \
     -smp 2                                                             \
     -m 256                                                             \
     -kernel $KERN                                                      \
     -hda $DISK                                                         \
     -no-reboot                                                         \
     -append "root=/dev/hda console=ttyS0 $cmds"                        \
     -nographic                                                         \
     -mtrace-enable                                                     \
     -mtrace-file $OUT
