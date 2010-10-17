/*
 * Memory access tracing/logging
 */

#define QEMU_MTRACE
#include "mtrace-magic.h"
#include "mtrace-file.h"
#include "mtrace.h"

static int mtrace_enable = 0;
/*
 * XXX come up with some consitent output format
 */
static FILE *mtrace_file;

void mtrace_init(void)
{
    if (mtrace_file == NULL)
	mtrace_file = stderr;
    /*
     * XXX this would be a good place to setup the data structures to
     * log the last core to write to a cache line.
     */
}

void mtrace_log_file_set(const char *path)
{
    mtrace_file = fopen(path, "w");
    if (mtrace_file == NULL) {
	perror("mtrace: fopen");
	exit(1);
    }
}

static void mtrace_dump_access(const char *prefix, 
			       target_ulong host_addr, 
			       target_ulong guest_addr)
{
    if (!mtrace_enable)
	return;

    fprintf(mtrace_file, "%-3s [%-3u %016lx  %016lx  %016lx]\n", 
	    prefix,
	    cpu_single_env->cpu_index, 
	    cpu_single_env->eip,
	    host_addr, 
	    guest_addr);
}

static void mtrace_dump_type(struct mtrace_type_entry *type)
{
    fprintf(mtrace_file, "%-3s [%-16s  %016lx  %016lx  %016lx]\n",
	    "T",
	    type->str,
	    type->host_addr,
	    type->guest_addr,
	    type->bytes);
}

void mtrace_st(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_dump_access("S", host_addr, guest_addr);
}

void mtrace_ld(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_dump_access("L", host_addr, guest_addr);
}

void mtrace_io_write(void *cb, target_phys_addr_t ram_addr, 
		    target_ulong guest_addr)
{
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
	mtrace_dump_access("IW", (unsigned long) 
			   qemu_get_ram_ptr(ram_addr), 
			   guest_addr);
    }
}

void mtrace_io_read(void *cb, target_phys_addr_t ram_addr, target_ulong guest_addr)
{
    /* Nothing to do.. */
}

/*
 * Handlers for the mtrace magic instruction
 */

static void mtrace_enable_set(target_ulong b, target_ulong a2,
			      target_ulong a3, target_ulong a4,
			      target_ulong a5)
{
    mtrace_enable = !!b;
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

static void mtrace_type_register(target_ulong guest_addr, target_ulong bytes, 
				 target_ulong str_addr, target_ulong n, 
				 target_ulong a5)
{
    struct mtrace_type_entry type;
    int r;

    if (n > sizeof(type.str) - 1)
	n = sizeof(type.str) - 1;
    
    r = cpu_memory_rw_debug(cpu_single_env, str_addr, (uint8_t *)type.str, n, 0);
    if (r) {
	fprintf(stderr, "mtrace_type_register: cpu_memory_rw_debug failed\n");
	return;
    }
    type.str[n] = 0;

    /*
     * XXX bug -- guest_addr might cross multiple host memory allocations,
     * which means the [host_addr, host_addr + bytes] is not contiguous.
     *
     * A simple solution is probably to log multiple mtrace_type_entrys.
     */
    r = mtrace_host_addr(guest_addr, &type.host_addr);
    if (r) {
	fprintf(stderr, "mtrace_type_register: mtrace_host_addr failed\n");
	return;
    }

    type.guest_addr = guest_addr;
    type.bytes = bytes;

    mtrace_dump_type(&type);
}

static void (*mtrace_call[])(target_ulong, target_ulong, target_ulong,
			     target_ulong, target_ulong) = 
{
    [MTRACE_ENABLE_SET]		= mtrace_enable_set,
    [MTRACE_TYPE_REGISTER] 	= mtrace_type_register,
};

void mtrace_inst_exec(target_ulong a0, target_ulong a1, 
		      target_ulong a2, target_ulong a3,
		      target_ulong a4, target_ulong a5)
{
    if (a0 >= sizeof(mtrace_call) / sizeof(mtrace_call[0]) ||
	mtrace_call[a0] == NULL) 
    {
	fprintf(stderr, "mtrace_inst_exec: bad call %lu\n", a0);
	return;
    }
    
    mtrace_call[a0](a1, a2, a3, a4, a5);
}
