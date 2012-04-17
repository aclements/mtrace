/*
 * Memory access tracing/logging
 *
 * Copyright (c) 2010 Silas Boyd-Wickizer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Send feedback to: Silas Boyd-Wickizer <sbw@mit.edu>
 */

#define QEMU_MTRACE
#include "mtrace-magic.h"
#include "mtrace.h"
#include "sysemu.h"

#include <sys/wait.h>

/* 64-byte cache lines */
#define MTRACE_CLINE_SHIFT	6

/* From dyngen-exec.h */
#define MTRACE_GETPC() ((void *)((unsigned long)__builtin_return_address(0) - 1))

/* Bytes of log data to buffer before shipping it to gzip */
#define FLUSH_BUFFER_BYTES 8192

static int mtrace_system_enable;
static mtrace_record_mode_t mtrace_mode;
static int mtrace_lock_trace;

static int mtrace_file;
static int mtrace_cline_track = 1;
static int mtrace_sample = 1;
static int mtrace_quantum;

static uint64_t mtrace_access_count;
static int mtrace_call_stack_active[255];
static int mtrace_call_trace;
static volatile int mtrace_lock_active[255];

static pid_t child_pid;

static uint64_t mtrace_inst_count[255];
static int mtrace_count_disable[255];

/* Call stack tag by CPU */
static uint64_t mtrace_call_stack[255];

struct mtrace_call_stack_info
{
    uint64_t tag;
    int ascope_depth;
} mtrace_per_call_stack[0x8000];

void mtrace_inst_inc(void)
{
    if (mtrace_count_disable[cpu_single_env->cpu_index])
        return;
    mtrace_inst_count[cpu_single_env->cpu_index]++;
}

void mtrace_cline_trace_set(int b)
{
    mtrace_cline_track = b;
}

void mtrace_lock_trace_set(int b)
{
    mtrace_lock_trace = b;
}

void mtrace_system_enable_set(int b)
{
    mtrace_system_enable = b;
}

int mtrace_system_enable_get(void)
{
    return mtrace_system_enable;
}

void mtrace_call_trace_set(int b)
{
    mtrace_call_trace = b;
}

void mtrace_sample_set(int n)
{
    mtrace_sample = n;
}

int mtrace_enable_get(void)
{
    return mtrace_mode != 0;
}

void mtrace_quantum_set(int n)
{
    mtrace_quantum = n;
}

int mtrace_quantum_get(void)
{
    return mtrace_quantum;
}

void mtrace_log_file_set(const char *path)
{
    int outfd, p[2], check[2], child, r;
    struct stat st;

    outfd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0666);
    if (outfd < 0) {
        perror("mtrace: open");
        abort();
    }
    if (fstat(outfd, &st) < 0) {
	perror("mtrace: fstat");
	abort();
    }
    if (S_ISFIFO(st.st_mode)) {
	mtrace_file = outfd;
	return;
    }

    if (pipe(p) < 0 || pipe(check) < 0) {
	perror("mtrace: pipe");
	abort();
    }
    if (fcntl(check[1], F_SETFD,
	      fcntl(check[1], F_GETFD, 0) | FD_CLOEXEC) < 0) {
	perror("mtrace: fcntl");
	abort();
    }

    child = fork();
    if (child < 0) {
	perror("mtrace: fork");
	abort();
    } else if (child == 0) {
	close(check[0]);
	dup2(outfd, 1);
	close(outfd);
	dup2(p[0], 0);
	close(p[0]);
	close(p[1]);
	r = execlp("gzip", "gzip", NULL);
	r = write(check[1], &r, sizeof(r));
	exit(0);
    }
    close(outfd);
    close(p[0]);
    close(check[1]);

    if (read(check[0], &r, sizeof(r)) != 0) {
	errno = r;
	perror("mtrace: exec");
	abort();
    }
    close(check[0]);

    child_pid = child;
    mtrace_file = p[1];
}

static void write_all(int fd, const void *data, size_t len)
{
    while (len) {
	ssize_t r = write(fd, data, len);
	if (r < 0) {
	    if (errno == EINTR)
		continue;
	    perror("write_all: write");
	    abort();
	}
	len -= r;
	data += r;
    }
}

static void mtrace_log_entry(union mtrace_entry *entry)
{
    static uint8_t flush_buffer[FLUSH_BUFFER_BYTES];
    static int n;

    if (entry == NULL) {
	write_all(mtrace_file, flush_buffer, n);
	n = 0;
	return;
    }

    if (n + entry->h.size > FLUSH_BUFFER_BYTES) {
	write_all(mtrace_file, flush_buffer, n);
	n = 0;
    }
    
    if (entry->h.size > FLUSH_BUFFER_BYTES)
	write_all(mtrace_file, entry, entry->h.size);
    else {
	memcpy(&flush_buffer[n], entry, entry->h.size);
	n += entry->h.size;
    }
}

static struct mtrace_call_stack_info *mtrace_get_per_call_stack(uint64_t tag)
{
    const int buckets = sizeof(mtrace_per_call_stack) / sizeof(mtrace_per_call_stack[0]);
    int i;
    for (i = 0; i < buckets; i++) {
	unsigned bucket = (tag + i) % buckets;
	struct mtrace_call_stack_info *cs = &mtrace_per_call_stack[bucket];
	if (cs->tag == tag) {
	    return cs;
	} else if (cs->tag == 0) {
	    *cs = (struct mtrace_call_stack_info){.tag = tag};
	    return cs;
	}
    }
    fprintf(stderr, "mtrace_per_call_stack hash table full\n");
    abort();
}

static void mtrace_del_per_call_stack(uint64_t tag)
{
    const int buckets = sizeof(mtrace_per_call_stack) / sizeof(mtrace_per_call_stack[0]);
    struct mtrace_call_stack_info *found = NULL, *last = NULL;
    int i;
    for (i = 0; i < buckets; i++) {
	unsigned bucket = (tag + i) % buckets;
	last = &mtrace_per_call_stack[bucket];
	if (last->tag == tag) {
	    found = last;
	} else if (last->tag == 0) {
	    break;
	}
    }
    if (found == last || found == NULL)
	return;
    *found = *last;
    last->tag = 0;
}

static struct mtrace_call_stack_info *mtrace_my_call_stack(int cpu)
{
    return mtrace_get_per_call_stack(mtrace_call_stack[cpu]);
}

#if 0
static unsigned long mtrace_get_pc(unsigned long searched_pc)
{
    return cpu_single_env->eip;
}
#endif

static unsigned long mtrace_get_pc(unsigned long searched_pc)
{
    mtrace_record_mode_t mtrace_mode_save;
    TranslationBlock *tb;

    /*
     * If searched_pc is NULL, or we can't find a TB, then cpu_single_env->eip 
     * is (hopefully, probably?) up-to-date.  This happens, for example, when
     * generating micro ops.
     */
    if (searched_pc == 0)
	return cpu_single_env->eip;

    /*
     * This is pretty heavy weight.  It doesn't look like QEMU saves the 
     * mappings required to translated a TCG code PC into a guest PC.  So, we:
     *
     *  1. find the TB for the TCG code PC (searched_pc)
     *  Call cpu_restore_state, which:
     *  2. generates the micro ops
     *  3. finds the offset of the micro op that corresponds to searched_pc's 
     *     offset in the TCG code of the TB
     *  4. uses gen_opc_pc to convert the offset of the micro op into a guest 
     *     PC
     *  5. updates cpu_single_env->eip
     *
     *  NB QEMU reads guest memory while generating micro ops.  We want to
     *  ignore these accesses, so we temporarily set mtrace_mode to 0.
     */
    tb = tb_find_pc(searched_pc);
    if (!tb)
	return cpu_single_env->eip;

    mtrace_mode_save = mtrace_mode;
    mtrace_mode = 0;
    cpu_restore_state(tb, cpu_single_env, searched_pc, NULL);
    mtrace_mode = mtrace_mode_save;

    return cpu_single_env->eip;
}

static void mtrace_access_dump(mtrace_access_t type, target_ulong host_addr, 
			       target_ulong guest_addr, 
			       unsigned long access_count,
			       void *retaddr,
			       int traffic,
			       int lock,
                               char bytes)
{
    struct mtrace_access_entry entry;
    static int sampler;
    
    if (!mtrace_mode)
	return;
    if (sampler++ % mtrace_sample)
	return;

    entry.h.type = mtrace_entry_access;
    entry.h.size = sizeof(entry);
    entry.h.cpu = cpu_single_env->cpu_index;
    entry.h.access_count = access_count;
    entry.h.ts = 0; /* Unimplemented timestamp */
    entry.access_type = type;
    entry.pc = mtrace_get_pc((unsigned long)retaddr);
    entry.host_addr = host_addr;
    entry.guest_addr = guest_addr;
    entry.traffic = traffic;
    entry.lock = lock;
    entry.bytes = bytes;

    mtrace_log_entry((union mtrace_entry *)&entry);
}

static int mtrace_cline_update_ld(uint8_t * host_addr, unsigned int cpu)
{
    unsigned long offset;
    RAMBlock *block;

    if (!mtrace_cline_track)
	return 1;

    block = qemu_ramblock_from_host(host_addr);
    offset = host_addr - block->host;

    if (mtrace_mode == mtrace_record_ascope) {
	/* Abstract scope mode.  Everything gets tracked.  We rely on
	 * higher-level filtering in mtrace_access_enabled, so we only
	 * get here if this access is performed by code running in an
	 * ascope.  We could filter to unique accesses only (we used
	 * to), but we'd have to track this per-ascope (or at least
	 * per-CPU) since multiple ascopes can be running in
	 * parallel. */
	return 1;
    } else {
        unsigned long cline = offset >> MTRACE_CLINE_SHIFT;

	/* Movement mode.  Each bit records a CPU. */
	if (block->cline_track[cline] & (1 << cpu))
	    return 0;

	block->cline_track[cline] |= (1 << cpu);
	return 1;
    }
}

static int mtrace_cline_update_st(uint8_t *host_addr, unsigned int cpu)
{
    unsigned long offset;
    RAMBlock *block;

    if (!mtrace_cline_track)
	return 1;

    block = qemu_ramblock_from_host(host_addr);
    offset = host_addr - block->host;

    if (mtrace_mode == mtrace_record_ascope) {
	return 1;
    } else {
	unsigned long cline = offset >> MTRACE_CLINE_SHIFT;

	/* Movement mode. */
	if (block->cline_track[cline] == (1 << cpu))
	    return 0;

	block->cline_track[cline] = (1 << cpu);
	return 1;
    }
}

static inline int mtrace_access_enabled(void)
{
    if (!mtrace_system_enable || !mtrace_mode)
	return 0;
    if (mtrace_mode == mtrace_record_ascope &&
	mtrace_my_call_stack(cpu_single_env->cpu_index)->ascope_depth == 0)
	return 0;
    return 1;
}

void mtrace_st(target_ulong host_addr, target_ulong guest_addr, char bytes, void *retaddr)
{
    uint64_t a;
    int lock;
    int r;

    if (!mtrace_access_enabled())
	return;

    a = mtrace_access_count++;

    r = mtrace_cline_update_st((uint8_t *)host_addr, 
			       cpu_single_env->cpu_index);
    lock = mtrace_lock_active[cpu_single_env->cpu_index];
    if (r || lock)
	mtrace_access_dump(mtrace_access_st, host_addr, guest_addr, 
			   a, retaddr, r, lock, bytes);
}

void mtrace_tcg_st(target_ulong host_addr, target_ulong guest_addr, char bytes)
{
    mtrace_st(host_addr, guest_addr, bytes, MTRACE_GETPC());
}

void mtrace_ld(target_ulong host_addr, target_ulong guest_addr, char bytes, void *retaddr)
{
    uint64_t a;
    int lock;
    int r;

    if (!mtrace_access_enabled())
	return;

    a = mtrace_access_count++;

    r = mtrace_cline_update_ld((uint8_t *)host_addr, 
			       cpu_single_env->cpu_index);
    lock = mtrace_lock_active[cpu_single_env->cpu_index];
    if (r || lock)
	mtrace_access_dump(mtrace_access_ld, host_addr, guest_addr, 
			   a, retaddr, r, lock, bytes);
}

void mtrace_tcg_ld(target_ulong host_addr, target_ulong guest_addr, char bytes)
{
    mtrace_ld(host_addr, guest_addr, bytes, MTRACE_GETPC());
}

void mtrace_io_write(void *cb, target_phys_addr_t ram_addr, 
		     target_ulong guest_addr, char bytes, void *retaddr)
{
    if (!mtrace_access_enabled())
	return;

    /*
     * XXX This is a hack -- I'm trying to log the host address and the
     * guest address without adding an extra argument to the CPUWriteMemoryFunc
     * and CPUReadMemoryFunc callbacks.
     * 
     */
    if (cb == notdirty_mem_writel ||
	cb == notdirty_mem_writew ||
	cb == notdirty_mem_writeb)
    {
	uint64_t a;
	int lock;
	int r;

	a = mtrace_access_count++;

	r = mtrace_cline_update_st(qemu_get_ram_ptr(ram_addr),
				   cpu_single_env->cpu_index);
	lock = mtrace_lock_active[cpu_single_env->cpu_index];
	if (r || lock)
	    mtrace_access_dump(mtrace_access_iw, 
			       (unsigned long) qemu_get_ram_ptr(ram_addr), 
			       guest_addr, a, retaddr, r, lock, bytes);
    }
}

void mtrace_io_read(void *cb, target_phys_addr_t ram_addr, 
		    target_ulong guest_addr, char bytes, void *retaddr)
{
    /* Nothing to do.. */
}

static inline uint64_t mtrace_get_percore_tsc(CPUX86State *env)
{
    return mtrace_inst_count[env->cpu_index];
}

static inline uint64_t mtrace_get_global_tsc(CPUX86State *env)
{
    uint64_t t;
    int i;

    t = 0;
    for (i = 0; i < smp_cpus; i++)
	t += mtrace_inst_count[i];
    return t;
}

void mtrace_lock_start(CPUX86State *env)
{
    if (!mtrace_lock_trace)
	return;

    if (mtrace_lock_active[env->cpu_index]) {
	/*
	 * XXX occasionally QEMU re-executes the microp that calls
	 * gen_helper_lock (which calls this function).  It seems
	 * harmless to ignore this weirdness for now.
	 *
	 * NB the spin_lock in gen_helper_lock is actually a NOP.
	 */
#if 0
	fprintf(stderr, "mtrace_lock_start: already lock start\n");
	abort();
#endif
    }
    mtrace_lock_active[env->cpu_index] = 1;
}

void mtrace_lock_stop(CPUX86State *env)
{
    if (!mtrace_lock_trace)
	return;

    if (!mtrace_lock_active[env->cpu_index]) {
	fprintf(stderr, "mtrace_lock_stop: no lock start\n");
	abort();
    }
    mtrace_lock_active[env->cpu_index] = 0;
}

static int mtrace_host_addr(target_ulong guest_addr, target_ulong *host_addr)
{
    target_phys_addr_t phys;
    target_phys_addr_t page;
    unsigned long pd;
    PhysPageDesc *p;
    void *ptr;

    phys = cpu_get_phys_page_debug(cpu_single_env, guest_addr);
    if (phys == -1)
	return -1;
    phys += (guest_addr & ~TARGET_PAGE_MASK);

    page = phys & TARGET_PAGE_MASK;
    p = phys_page_find(page >> TARGET_PAGE_BITS);
    if (!p)
	return -1;

    pd = p->phys_offset;
    if ((pd & ~TARGET_PAGE_MASK) > IO_MEM_ROM && !(pd & IO_MEM_ROMD)) {
	/*
	 * XXX bug -- handle IO crud (cpu_physical_memory_rw has an exmaple)
	 * This might be unnecessary on x86.
	 */
	return -1;
    }

    ptr = qemu_get_ram_ptr(pd & TARGET_PAGE_MASK) + (phys & ~TARGET_PAGE_MASK);
    *host_addr = (target_ulong)ptr;
    return 0;
}

static void mtrace_reset_cline_track(mtrace_record_mode_t mode)
{
    RAMBlock *block;

    if (mode == mtrace_record_ascope)
	/* No tracking */
	return;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        ram_addr_t size;
        switch (mode) {
        case mtrace_record_movement:
            // One byte per cache line
            size = block->length >> MTRACE_CLINE_SHIFT;
            break;
        default:
            fprintf(stderr, "bad record mode %d\n", mode);
            abort();
        }

        if (block->cline_track && block->cline_track_size < size) {
            mtrace_cline_track_free(block);
        }
        if (!block->cline_track) {
            block->cline_track = qemu_vmalloc(size);
            if (!block->cline_track) {
                perror("qemu_vmalloc failed\n");
                abort();
            }
            /*
             * Could use qemu_madvise(MADV_MERGEABLE) if
             * size >> MTRACE_CLINE_SHIFT is large
             */
            block->cline_track_size = size;
        }
        memset(block->cline_track, 0xff, size);
    }
}

/*
 * Handler for the mtrace magic instruction
 */
static void mtrace_entry_register(target_ulong entry_addr, target_ulong type,
                                  target_ulong len, target_ulong n4,
                                  target_ulong n5)
{
    union mtrace_entry entry;
    int r;

    if (len > sizeof(entry)) {
	fprintf(stderr, "mtrace_entry_register: entry too big: %lu > %u\n",
		(unsigned long)len, (unsigned)sizeof(entry));
	return;
    }

    /* (Could skip copying the header) */
    r = cpu_memory_rw_debug(cpu_single_env, entry_addr, (uint8_t *)&entry, len, 0);
    if (r) {
	fprintf(stderr, "mtrace_entry_register: cpu_memory_rw_debug failed\n");
	return;
    }

    entry.h.type = type;
    entry.h.size = len;
    entry.h.cpu = cpu_single_env->cpu_index;
    entry.h.access_count = mtrace_access_count;
    entry.h.ts = mtrace_get_percore_tsc(cpu_single_env);

    /* Special handling */
    if (type == mtrace_entry_label) {
	/*
	 * XXX bug -- guest_addr might cross multiple host memory allocations,
	 * which means the [host_addr, host_addr + bytes] is not contiguous.
	 *
	 * A simple solution is probably to log multiple mtrace_label_entrys.
	 */
	r = mtrace_host_addr(entry.label.guest_addr, &entry.label.host_addr);
	if (r) {
	    fprintf(stderr, "mtrace_entry_register: mtrace_host_addr failed (%"PRIx64")\n", 
		    entry.label.guest_addr);
	    return;
	}
    }

    /* Special handling */
    if (type == mtrace_entry_host) {
	entry.host.global_ts = mtrace_get_global_tsc(cpu_single_env);
	switch (entry.host.host_type) {
	case mtrace_access_all_cpu:
	    if (entry.host.access.mode && entry.host.access.mode != mtrace_mode)
		mtrace_reset_cline_track(entry.host.access.mode);
	    mtrace_mode = entry.host.access.mode;
	    break;
	case mtrace_call_clear_cpu:
            if (entry.host.call.cpu == ~0UL)
                mtrace_call_stack_active[cpu_single_env->cpu_index] = 0;
            else
                mtrace_call_stack_active[entry.host.call.cpu] = 0;
	    break;
	case mtrace_call_set_cpu:
	    /* Only enable call traces when mtrace_enable */
            if (entry.host.call.cpu == ~0UL)
                mtrace_call_stack_active[cpu_single_env->cpu_index] = mtrace_mode;
            else
                mtrace_call_stack_active[entry.host.call.cpu] = mtrace_mode;
	    break;
        case mtrace_disable_count_cpu:
            mtrace_count_disable[cpu_single_env->cpu_index] = 1;
            /* No point in logging this */
            return;
        case mtrace_enable_count_cpu:
            mtrace_count_disable[cpu_single_env->cpu_index] = 0;
            /* No point in logging this */
            return;
	default:
	    fprintf(stderr, "bad mtrace_entry_host type %u\n", 
		    entry.host.host_type);
	    abort();
	}
    } 

    /* Track call stacks for filtering purposes */
    if (type == mtrace_entry_fcall) {
	int cpu = entry.h.cpu;
	uint64_t tag = entry.fcall.tag;
	switch (entry.fcall.state) {
	case mtrace_start:
	case mtrace_resume:
	    mtrace_call_stack[cpu] = tag;
	    break;
	case mtrace_done:
	    mtrace_del_per_call_stack(tag);
	case mtrace_pause:
	    mtrace_call_stack[cpu] = 0;
	    break;
	}
    }

    /* Special handling for abstract scopes */
    if (type == mtrace_entry_ascope) {
	if (entry.ascope.exit)
	    mtrace_my_call_stack(entry.h.cpu)->ascope_depth--;
	else
	    mtrace_my_call_stack(entry.h.cpu)->ascope_depth++;
    }

    /* Special handling for locks */
    if (type == mtrace_entry_lock) {
	/* Only record lock operations in movement mode */
	if (mtrace_mode != mtrace_record_movement)
	    return;
    }

    mtrace_log_entry(&entry);
}

static void (*mtrace_call[])(target_ulong, target_ulong, target_ulong,
			     target_ulong, target_ulong) = 
{
    [MTRACE_ENTRY_REGISTER]	= mtrace_entry_register,
};

void mtrace_inst_exec(target_ulong a0, target_ulong a1, 
		      target_ulong a2, target_ulong a3,
		      target_ulong a4, target_ulong a5)
{
    if (!mtrace_system_enable)
	return;

    if (a0 >= sizeof(mtrace_call) / sizeof(mtrace_call[0]) ||
	mtrace_call[a0] == NULL) 
    {
	fprintf(stderr, "mtrace_inst_exec: bad call %"PRIu64"\n", a0);
	abort();
    }
    
    mtrace_call[a0](a1, a2, a3, a4, a5);
}

void mtrace_inst_call(target_ulong target_pc, target_ulong return_pc,
		      int ret)
{
    struct mtrace_call_entry call;    
    int cpu;

    if (!mtrace_system_enable || !mtrace_call_trace)
	return;

    cpu = cpu_single_env->cpu_index;

    if (!mtrace_call_stack_active[cpu])
	return;

    call.h.type = mtrace_entry_call;
    call.h.size = sizeof(call);
    call.h.cpu = cpu;
    call.h.access_count = mtrace_access_count;
    
    call.target_pc = target_pc;
    call.return_pc = return_pc;
    call.ret = ret;

    mtrace_log_entry((union mtrace_entry *)&call);
}

void mtrace_cline_track_free(RAMBlock *block)
{
    if (block->cline_track)
	qemu_vfree(block->cline_track);
    block->cline_track = NULL;
    block->cline_track_size = 0;
}

static void mtrace_cleanup(void)
{
    if (mtrace_file) {
	mtrace_log_entry(NULL);
	close(mtrace_file);
	if (child_pid) {
	    if (waitpid(child_pid, NULL, 0) < 0) {
		if (errno != ECHILD && errno != EINTR) {
		    perror("mtrace_cleanup: waitpid");
		    abort();
		}
	    }
	}
    }
    mtrace_file = 0;
}

void mtrace_init(void)
{
    struct mtrace_machine_entry entry;

    if (!mtrace_system_enable)
	return;

    if (mtrace_file == 0)
	mtrace_log_file_set("mtrace.out");

    entry.h.type = mtrace_entry_machine;
    entry.h.size = sizeof(entry);
    entry.h.cpu = 0;
    entry.h.access_count = mtrace_access_count;
    entry.h.ts = 0;

    entry.num_cpus = smp_cpus;
    entry.num_ram = ram_size;
    entry.quantum = mtrace_quantum;
    entry.sample = mtrace_sample;
    entry.locked = mtrace_lock_trace;
    entry.calls = mtrace_call_trace;
    mtrace_log_entry((union mtrace_entry *)&entry);
    
    atexit(mtrace_cleanup);
}
