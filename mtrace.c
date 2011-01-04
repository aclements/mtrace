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
static FILE *mtrace_file;
static void (*mtrace_log_entry)(union mtrace_entry *);
static int mtrace_cline_track = 1;
static uint64_t mtrace_access_count;
static int mtrace_call_stack_active[255];
static int mtrace_call_trace;

void mtrace_log_file_set(const char *path)
{
    mtrace_file = fopen(path, "w");
    if (mtrace_file == NULL) {
	perror("mtrace: fopen");
	abort();
    }
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

static void mtrace_log_entry_text(union mtrace_entry *entry)
{
    static const char *access_type_to_str[] = {
	[mtrace_access_ld] = "ld",
	[mtrace_access_st] = "st",
	[mtrace_access_iw] = "iw",
    };

    switch(entry->type) {
    case mtrace_entry_label:
	fprintf(mtrace_file, "%-3s [%-3u  %16s  %016lx  %016lx  %016lx  %016lx]\n",
		"T",
		entry->label.label_type,
		entry->label.str,
		entry->label.host_addr,
		entry->label.guest_addr,
		entry->label.bytes,
		entry->label.access_count);
	break;
    case mtrace_entry_access:
	fprintf(mtrace_file, "%-3s [%-3u %16lu  %016lx  %016lx  %016lx]\n", 
		access_type_to_str[entry->access.access_type],
		entry->access.cpu,
		entry->access.access_count,
		entry->access.pc,
		entry->access.host_addr,
		entry->access.guest_addr);
	break;
    case mtrace_entry_enable:
	fprintf(mtrace_file, "%-3s [%u]\n", 
		"E", entry->enable.enable);
	break;
    case mtrace_entry_fcall:
	fprintf(mtrace_file, "%-3s [%-3u  %16lu  %16lu  %016lx"
		"  %016lx  %4u  %1u]\n",
		"C",
		entry->fcall.cpu,
		entry->fcall.access_count,
		entry->fcall.tid,
		entry->fcall.pc,
		entry->fcall.tag,
		entry->fcall.depth,
		entry->fcall.state);
	break;
    case mtrace_entry_segment:
	fprintf(mtrace_file, "%-3s [%-3u  %3u  %16lx %16lx]\n",
		"S",
		entry->seg.cpu,
		entry->seg.type,
		entry->seg.baseaddr,
		entry->seg.endaddr);
	break;
    case mtrace_entry_call:
	fprintf(mtrace_file, "%-3s [%-3u  %4s  %16lu  %16lx %16lx]\n",
		"L",
		entry->call.cpu,
		entry->call.ret ? "ret" : "call",
		entry->call.access_count,
		entry->call.target_pc,
		entry->call.return_pc);
	break;
    default:
	fprintf(stderr, "mtrace_log_entry: bad type %u\n", entry->type);
	abort();
    }
}

static void mtrace_log_entry_binary(union mtrace_entry *entry)
{
    size_t r, n;

    switch(entry->type) {
    case mtrace_entry_label:
	n = sizeof(struct mtrace_label_entry);
	break;
    case mtrace_entry_access:
	n = sizeof(struct mtrace_access_entry);
	break;
    case mtrace_entry_enable:
	n = sizeof(struct mtrace_enable_entry);
	break;
    case mtrace_entry_fcall:
	n = sizeof(struct mtrace_fcall_entry);
	break;
    case mtrace_entry_segment:
	n = sizeof(struct mtrace_segment_entry);
	break;
    case mtrace_entry_call:
	n = sizeof(struct mtrace_call_entry);
	break;
    default:
	fprintf(stderr, "mtrace_log_entry: bad type %u\n", entry->type);
	abort();
    }

    r = fwrite(entry, n, 1, mtrace_file);
    if (r != 1) {
	perror("mtrace_log_entry_binary: fwrite");
	abort();
    }
}

void mtrace_format_set(const char *id)
{
    static struct {
	const char *id;
	void (*fn)(union mtrace_entry *);
    } format[] = {
	{ "text", mtrace_log_entry_text },
	{ "binary", mtrace_log_entry_binary },
    };

    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(format); i++) {
	if (!strcmp(id, format[i].id)) {
	    mtrace_log_entry = format[i].fn;
	    return;
	}
    }

    fprintf(stderr, "mtrace_format_set: bad format %s\n", id);
    abort();
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
    
    if (!mtrace_enable)
	return;
    
    entry.type = mtrace_entry_access;
    entry.access_type = type;
    entry.cpu = cpu_single_env->cpu_index;
    entry.pc = mtrace_get_pc((unsigned long)retaddr);
    entry.host_addr = host_addr;
    entry.guest_addr = guest_addr;
    entry.access_count = access_count;

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
    enable.type = mtrace_entry_enable;
    enable.access_count = mtrace_access_count;
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

static void mtrace_label_register(target_ulong label_addr, target_ulong n2, 
				  target_ulong n3, target_ulong n4, 
				  target_ulong n5)
{
    struct mtrace_label_entry label;
    int r;

    r = cpu_memory_rw_debug(cpu_single_env, label_addr, (uint8_t *)&label, sizeof(label), 0);
    if (r) {
	fprintf(stderr, "mtrace_label_register: cpu_memory_rw_debug failed\n");
	return;
    }

    label.access_count = mtrace_access_count;
    label.str[sizeof(label.str) - 1] = 0;
    label.type = mtrace_entry_label;

    /*
     * XXX bug -- guest_addr might cross multiple host memory allocations,
     * which means the [host_addr, host_addr + bytes] is not contiguous.
     *
     * A simple solution is probably to log multiple mtrace_label_entrys.
     */
    r = mtrace_host_addr(label.guest_addr, &label.host_addr);
    if (r) {
	fprintf(stderr, "mtrace_label_register: mtrace_host_addr failed (%lx)\n", 
		label.guest_addr);
	return;
    }

    mtrace_log_entry((union mtrace_entry *)&label);
}

static void mtrace_fcall_register(target_ulong tid, target_ulong pc, 
				  target_ulong tag, target_ulong depth, 
				  target_ulong state)
{
    struct mtrace_fcall_entry fcall;
    int cpu;

    cpu = cpu_single_env->cpu_index;

    fcall.type = mtrace_entry_fcall;
    fcall.tid = tid;
    fcall.pc = pc;
    fcall.tag = tag;
    fcall.depth = depth;
    fcall.state = state;
    fcall.cpu = cpu;
    fcall.access_count = mtrace_access_count;

    mtrace_log_entry((union mtrace_entry *)&fcall);
    mtrace_call_stack_active[cpu] = 
	(state == mtrace_start || state == mtrace_resume);
}

static void mtrace_segment_register(target_ulong baseaddr, target_ulong endaddr,
				    target_ulong type, target_ulong cpu, 
				    target_ulong a4)
{
    struct mtrace_segment_entry seg;

    seg.type = mtrace_entry_segment;
    seg.access_count = mtrace_access_count;

    seg.object_type = type;
    seg.baseaddr = baseaddr;
    seg.endaddr = endaddr;
    seg.cpu = cpu;

    mtrace_log_entry((union mtrace_entry *)&seg);
}

static void (*mtrace_call[])(target_ulong, target_ulong, target_ulong,
			     target_ulong, target_ulong) = 
{
    [MTRACE_ENABLE_SET]		= mtrace_enable_set,
    [MTRACE_LABEL_REGISTER] 	= mtrace_label_register,
    [MTRACE_FCALL_REGISTER]	= mtrace_fcall_register,
    [MTRACE_SEGMENT_REGISTER]	= mtrace_segment_register,
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
    
    call.type = mtrace_entry_call;
    call.access_count = mtrace_access_count;
    
    call.cpu = cpu;
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

void mtrace_init(void)
{
    if (!mtrace_system_enable)
	return;

    if (mtrace_file == NULL)
	mtrace_file = stderr;
    if (mtrace_log_entry == NULL)
	mtrace_log_entry = mtrace_log_entry_text;
}
