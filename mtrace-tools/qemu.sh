#!/bin/sh

cmds='run-cmdline="/root/fops-dir 1 2 /root/tmp/foo 1" '
cmds=$cmds'run-cmdline="/root/proc-ping-pong 0 1 1" '
cmds=$cmds'run-cmdline="shutdown -h now"'

QEMU=~/local/bin/qemu-system-x86_64
DISK=~/img/qemu.img
KERN=~/linux-2.6/obj.qemu/arch/x86_64/boot/bzImage

$QEMU									\
     -smp 2								\
     -m 256								\
     -kernel $KERN							\
     -hda $DISK								\
     -append "root=/dev/hda console=ttyS0 $cmds"  			\
     -nographic								\
     -mtrace-file /tmp/mtrace.out -mtrace-format binary
