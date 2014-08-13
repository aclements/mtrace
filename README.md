mtrace is a version of [QEMU](http://www.qemu.org/) modified to log
memory accesses and other system events to help analyze and understand
the memory access patterns and cache line behavior of operating
system-level code.

mtrace includes mscan (in `mtrace-tools/`), which processes these log
files and implements a suite of analyses.

N.B.: Don't confuse QEMU's 'trace' features with mtrace.


Dependencies
------------

mscan depends on libelfin, which can be found at

    git clone https://github.com/aclements/libelfin.git

We recommend cloning and building libelfin next to the mtrace
repository, as mtrace will find it automatically.  Alternatively, you
can `make install` libelfin to install it system-wide.


Building
--------

Building mtrace is just like building QEMU.  We recommend a minimal
configuration, optimized for testing OS code:

    ./configure --prefix=PREFIX \
                --target-list="x86_64-softmmu" \
                --disable-kvm \
                --audio-card-list="" \
                --disable-vnc-jpeg \
                --disable-vnc-png \
                --disable-strip
    make

Then, to build mscan

    cd mtrace-tools && make

It's not necessary to `make install` either mtrace or mscan, though it
may be a good idea to add `x86_64-softmmu/` and `mtrace-tools/` to
your `$PATH`:

    PATH=$PWD/x86_64-softmmu:$PWD/mtrace-tools:$PATH


Running a Linux kernel in mtrace
--------------------------------

Our mtrace-enabled version of Linux can be found at

    git clone https://github.com/aclements/linux-mtrace.git

We recommend configuring and building the kernel as follows.  The
first three configuration options are required to run the kernel in
mtrace.  The rest just disables large features that are likely to be
unnecessary.

    make defconfig
    # Enable DWARF info for mscan
    echo CONFIG_DEBUG_INFO=y >> .config
    # Reduce number of CPUs
    echo CONFIG_NR_CPUS=16 >> .config
    # Avoid live-lock with timer interrupts
    echo CONFIG_HZ_100=y >> .config
    # Enable devtmpfs
    echo CONFIG_DEVTMPFS=y >> .config
    # Enable RAM disk (for testing fsync, etc)
    echo CONFIG_BLK_DEV_RAM=y >> .config
    # Shrink the kernel
    echo CONFIG_PARTITION_ADVANCED=n >> .config
    echo CONFIG_SUSPEND=n >> .config
    echo CONFIG_HIBERNATION=n >> .config
    echo CONFIG_CPU_FREQ=n >> .config
    echo CONFIG_YENTA=n >> .config
    echo CONFIG_IPV6=n >> .config
    echo CONFIG_NETFILTER=n >> .config
    echo CONFIG_NET_SCHED=n >> .config
    echo CONFIG_ETHERNET=n >> .config
    echo CONFIG_HAMRADIO=n >> .config
    echo CONFIG_CFG80211=n >> .config
    echo CONFIG_AGP=n >> .config
    echo CONFIG_DRM=n >> .config
    echo CONFIG_FB=n >> .config
    echo CONFIG_SOUND=n >> .config
    echo CONFIG_USB=n >> .config
    echo CONFIG_I2C=n >> .config
    echo CONFIG_HID=n >> .config
    echo CONFIG_SECURITY_SELINUX=n >> .config
    make olddefconfig

    make

At this point, you can run this kernel in mtrace with

    qemu-system-x86_64 -mtrace-enable -mtrace-file mtrace.out \
      -kernel arch/x86_64/boot/bzImage -nographic -append console=ttyS0

It won't get very far without a disk or an initramfs to boot from, but
you should get an `mtrace.out` with some basic log records in it.  Try
`m2text mtrace.out` to get a feel for the log file.

See `qemu-system-x86_64 -help` for additional options that control
mtrace.


Running MOSBENCH in mtrace
--------------------------

See `README.mosbench`.


QEMU calls
----------

Guest code can call into qemu to turn mtracing on or off, communicate
object instances and types, etc.  See `mtrace-magic.h` for the current
API and the `linux-mtrace` repository for example usage.  There are
also some examples in MOSBENCH under `micro/`.


Cache line tracking
-------------------

When cache line tracking is enabled via a hypercall, memory accesses
are reported only when an access might cause inter-core traffic.
Specifically:

* mtrace records a *read* if its cache line was written to by another
  core since that last read from the reading core.
* mtrace records a *write* if its cache line that was read from or
  written to by another core since the last write from the writing
  core.

There is no other cache simulation (i.e. caches are fully associative
and have infinite capacity).


Implementation choices
----------------------

If we don't want the virtual address, we could modify the macros in
`cpu-all.h` (`stl_p`, ...).  We would still need the changes to the
x86 code gen in `tcg/i386/tcg_target.c`.


To do
-----

Minor things

- Move all mtrace* decls. to mtrace.h
- Report progress in mscan
- Connect user-space and syscall stacks so we can backtrace across the
  user/kernel boundary
- Many analyses could take a granularity option to control whether
  sharing is byte-level or line-level

mtrace is huge, full of cruft, and built on an ancient version of
QEMU.  We should lift out the parts we still use into a new version of
mtrace.  mtrace could be a great platform, but it's too much of a mess
right now.

Have a single library for reading mtrace logs.  Currently we have
separate log decoders at least in mscan and m2text, which means m2text
is consistently unable to dump recent logs.  This separation also
means we don't have a way to print log entries in mscan.  m2text
should be a trivial shell around printers in the common log library.

We currently hard-code several memory filtering policies, but it seems
like every new analysis needs a new filtering policy.  Make them
loadable .so's that can be specified on the QEMU command line.

Instead of having one giant mscan binary that we have to expand for
each new analysis, make each analysis its own binary and put common
code (like context tracking) in a `libmscan`.

Make mtrace require fewer or no kernel hooks:

* Eliminate stack-switching hypercalls.  We can detect stack switches
  automatically based on CR3 and current stack pointer, plus starting
  a new call stack when an interrupt occurs and terminating that call
  stack when its stack pointer goes above where the interrupt frame
  was pushed (while remaining in the same stack region).  These
  hypercalls are also really hard to add to all of the right places.

* Move allocation labeling into an honest-to-goodness module that's
  more easily portable across Linux versions.  This module could also
  help report information about stacks (e.g., when a new process stack
  is created, it could report its extend and information like process
  name).

  * Alternatively, mtrace could use kernel debug info to set QEMU
    breakpoints on the allocation function we care about.  This would
    require a little kernel-specific information, but would be less
    cumbersome than code modification and would support a wide range
    of kernels and kernel versions.  (Compared to stack-switching
    hypercalls, these are pretty easy to add, so this may be less
    valuable.)
