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

/* 64-byte cache lines */
#define MTRACE_CLINE_SHIFT	6

/* From dyngen-exec.h */
#define MTRACE_GETPC() ((void *)((unsigned long)__builtin_return_address(0) - 1))

static int mtrace_system_enable;
static int mtrace_enable;
static int mtrace_file;
static int mtrace_cline_track = 1;
static uint64_t mtrace_access_count;
static int mtrace_call_stack_active[255];
static int mtrace_call_trace;

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

    mtrace_file = p[1];
}

void mtrace_cline_trace_set(int b)
{
    mtrace_cline_track = b;
}

void mtrace_system_enable_set(int b)
{
    mtrace_system_enable = b;
}

void mtrace_call_trace_set(int b)
{
    mtrace_call_trace = b;
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
    write_all(mtrace_file, entry, entry->h.size);
}

#if 0
static unsigned long mtrace_get_pc(unsigned long searched_pc)
{
    return cpu_single_env->eip;
}
#endif

static unsigned long mtrace_get_pc(unsigned long searched_pc)
{
    int mtrace_enable_save;
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
     *  ignore these accesses, so we temporarily set mtrace_enable to 0.
     */
    tb = tb_find_pc(searched_pc);
    if (!tb)
	return cpu_single_env->eip;

    mtrace_enable_save = mtrace_enable;
    mtrace_enable = 0;
    cpu_restore_state(tb, cpu_single_env, searched_pc, NULL);
    mtrace_enable = mtrace_enable_save;

    return cpu_single_env->eip;
}

static void mtrace_access_dump(mtrace_access_t type, target_ulong host_addr, 
			       target_ulong guest_addr, 
			       unsigned long access_count,
			       void *retaddr)
{
    struct mtrace_access_entry entry;
    static int sampler;
    
    if (!mtrace_enable)
	return;
    
    if (sampler++ % 20)
	return;

    entry.h.type = mtrace_entry_access;
    entry.h.size = sizeof(entry);
    entry.h.cpu = cpu_single_env->cpu_index;
    entry.h.access_count = access_count;
    entry.access_type = type;
    entry.pc = mtrace_get_pc((unsigned long)retaddr);
    entry.host_addr = host_addr;
    entry.guest_addr = guest_addr;

    mtrace_log_entry((union mtrace_entry *)&entry);
}

static int mtrace_cline_update_ld(uint8_t * host_addr, unsigned int cpu)
{
    unsigned long offset;
    unsigned long cline;
    RAMBlock *block;

    if (!mtrace_cline_track)
	return 1;

    block = qemu_ramblock_from_host(host_addr);
    offset = host_addr - block->host;
    cline = offset >> MTRACE_CLINE_SHIFT;

    if (block->cline_track[cline] & (1 << cpu))
	return 0;

    block->cline_track[cline] |= (1 << cpu);
    return 1;
}

static int mtrace_cline_update_st(uint8_t *host_addr, unsigned int cpu)
{
    unsigned long offset;
    unsigned long cline;
    RAMBlock *block;

    if (!mtrace_cline_track)
	return 1;

    block = qemu_ramblock_from_host(host_addr);
    offset = host_addr - block->host;
    cline = offset >> MTRACE_CLINE_SHIFT;

    if (block->cline_track[cline] == (1 << cpu))
	return 0;

    block->cline_track[cline] = (1 << cpu);
    return 1;
}

void mtrace_st(target_ulong host_addr, target_ulong guest_addr, void *retaddr)
{
    uint64_t a;
    int r;

    if (!mtrace_system_enable)
	return;

    a = mtrace_access_count++;

    r = mtrace_cline_update_st((uint8_t *)host_addr, 
			       cpu_single_env->cpu_index);
    if (r)
	mtrace_access_dump(mtrace_access_st, host_addr, guest_addr, a, retaddr);
}

void mtrace_tcg_st(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_st(host_addr, guest_addr, MTRACE_GETPC());
}

void mtrace_ld(target_ulong host_addr, target_ulong guest_addr, void *retaddr)
{
    uint64_t a;
    int r;

    if (!mtrace_system_enable)
	return;

    a = mtrace_access_count++;

    r = mtrace_cline_update_ld((uint8_t *)host_addr, 
			       cpu_single_env->cpu_index);
    if (r)
	mtrace_access_dump(mtrace_access_ld, host_addr, guest_addr, a, retaddr);
}

void mtrace_tcg_ld(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_ld(host_addr, guest_addr, MTRACE_GETPC());
}

void mtrace_io_write(void *cb, target_phys_addr_t ram_addr, 
		     target_ulong guest_addr, void *retaddr)
{
    if (!mtrace_system_enable)
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
	int r;

	a = mtrace_access_count++;

	r = mtrace_cline_update_st(qemu_get_ram_ptr(ram_addr),
				   cpu_single_env->cpu_index);
	if (r)
	    mtrace_access_dump(mtrace_access_iw, 
			       (unsigned long) qemu_get_ram_ptr(ram_addr), 
			       guest_addr, a, retaddr);
    }
}

void mtrace_io_read(void *cb, target_phys_addr_t ram_addr, 
		    target_ulong guest_addr, void *retaddr)
{
    /* Nothing to do.. */
}

/*
 * Handlers for the mtrace magic instruction
 */

static void mtrace_enable_set(target_ulong b, target_ulong str_addr,
			      target_ulong n, target_ulong a4,
			      target_ulong a5)
{
    struct mtrace_enable_entry enable;
    int r;

    mtrace_enable = !!b;
    enable.h.type = mtrace_entry_enable;
    enable.h.size = sizeof(enable);
    enable.h.cpu = 0;
    enable.h.access_count = mtrace_access_count;
    enable.enable = mtrace_enable;


    if (n > sizeof(enable.str) - 1)
	n = sizeof(enable.str) - 1;
    
    r = cpu_memory_rw_debug(cpu_single_env, str_addr, (uint8_t *)enable.str, n, 0);
    if (r) {
	fprintf(stderr, "mtrace_enable_set: cpu_memory_rw_debug failed\n");
	return;
    }
    enable.str[n] = 0;

    mtrace_log_entry((union mtrace_entry *)&enable);
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

static void mtrace_entry_register(target_ulong entry_addr, target_ulong type,
                                  target_ulong len, target_ulong cpu,
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
    if (cpu == ~0)
        entry.h.cpu = cpu_single_env->cpu_index;
    else
        entry.h.cpu = cpu;
    entry.h.access_count = mtrace_access_count;

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
	    fprintf(stderr, "mtrace_entry_register: mtrace_host_addr failed (%lx)\n", 
		    entry.label.guest_addr);
	    return;
	}
    }

    mtrace_log_entry(&entry);

    /* Special handling */
    if (type == mtrace_entry_fcall)
        mtrace_call_stack_active[entry.h.cpu] =
            (entry.fcall.state == mtrace_start ||
             entry.fcall.state == mtrace_resume);
    else if (type == mtrace_entry_lock && strcmp(entry.lock.str, "&mm->mmap_sem") == 0) {
        mtrace_enable = 1;
    }
}

static void (*mtrace_call[])(target_ulong, target_ulong, target_ulong,
			     target_ulong, target_ulong) = 
{
    [MTRACE_ENABLE_SET]		= mtrace_enable_set,
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
	fprintf(stderr, "mtrace_inst_exec: bad call %lu\n", a0);
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

uint8_t *mtrace_cline_track_alloc(size_t size)
{
    uint8_t *b;

    if (!mtrace_cline_track || !mtrace_system_enable)
	return NULL;

    b = qemu_vmalloc(size >> MTRACE_CLINE_SHIFT);
    if (b == NULL) {
	perror("qemu_vmalloc failed\n");
	abort();
    }
    /* 
     * Could use qemu_madvise(MADV_MERGEABLE) if 
     * size >> MTRACE_CLINE_SHIFT is large 
     */

    memset(b, 0, size >> MTRACE_CLINE_SHIFT);
    return b;
}

void mtrace_cline_track_free(uint8_t *cline_track)
{
    if (cline_track)
	qemu_vfree(cline_track);
}

static void mtrace_cleanup(void)
{
    if (mtrace_file)
	close(mtrace_file);
    mtrace_file = 0;
}

void mtrace_init(void)
{
    if (!mtrace_system_enable)
	return;

    if (mtrace_file == 0)
	mtrace_log_file_set("mtrace.out");
    atexit(mtrace_cleanup);
}
