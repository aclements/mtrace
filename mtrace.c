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

static void mtrace_log_entry(union mtrace_entry *entry)
{
    static const char *access_type_to_str[] = {
	[mtrace_access_ld] = "ld",
	[mtrace_access_st] = "st",
	[mtrace_access_iw] = "iw",
    };

    switch(entry->type) {
    case mtrace_entry_label:
	fprintf(mtrace_file, "%-3s [%-16s  %016lx  %016lx  %016lx]\n",
		"T",
		entry->label.str,
		entry->label.host_addr,
		entry->label.guest_addr,
		entry->label.bytes);
	break;
    case mtrace_entry_access:
	fprintf(mtrace_file, "%-3s [%-3u %016lx  %016lx  %016lx]\n", 
		access_type_to_str[entry->access.access_type],
		entry->access.cpu,
		entry->access.pc,
		entry->access.host_addr,
		entry->access.guest_addr);
	break;
    default:
	fprintf(stderr, "mtrace_log_entry: bad type %u\n", entry->type);
	exit(1);
    }
}

static void mtrace_access_dump(mtrace_access_t type, target_ulong host_addr, 
			       target_ulong guest_addr)
{
    struct mtrace_access_entry entry;
    
    if (!mtrace_enable)
	return;
    
    entry.type = mtrace_entry_access;
    entry.access_type = type;
    entry.cpu = cpu_single_env->cpu_index;
    /* XXX bug -- this EIP is the start of the TB */
    entry.pc = cpu_single_env->eip;
    entry.host_addr = host_addr;
    entry.guest_addr = guest_addr;

    mtrace_log_entry((union mtrace_entry *)&entry);
}

void mtrace_st(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_access_dump(mtrace_access_st, host_addr, guest_addr);
}

void mtrace_ld(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_access_dump(mtrace_access_ld, host_addr, guest_addr);
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
	mtrace_access_dump(mtrace_access_iw, 
			   (unsigned long) qemu_get_ram_ptr(ram_addr), 
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

static void mtrace_label_register(target_ulong guest_addr, target_ulong bytes, 
				 target_ulong str_addr, target_ulong n, 
				 target_ulong a5)
{
    struct mtrace_label_entry label;
    int r;

    if (n > sizeof(label.str) - 1)
	n = sizeof(label.str) - 1;
    
    r = cpu_memory_rw_debug(cpu_single_env, str_addr, (uint8_t *)label.str, n, 0);
    if (r) {
	fprintf(stderr, "mtrace_label_register: cpu_memory_rw_debug failed\n");
	return;
    }
    label.str[n] = 0;

    /*
     * XXX bug -- guest_addr might cross multiple host memory allocations,
     * which means the [host_addr, host_addr + bytes] is not contiguous.
     *
     * A simple solution is probably to log multiple mtrace_label_entrys.
     */
    r = mtrace_host_addr(guest_addr, &label.host_addr);
    if (r) {
	fprintf(stderr, "mtrace_label_register: mtrace_host_addr failed\n");
	return;
    }

    label.guest_addr = guest_addr;
    label.bytes = bytes;

    label.type = mtrace_entry_label;
    mtrace_log_entry((union mtrace_entry *)&label);
}

static void (*mtrace_call[])(target_ulong, target_ulong, target_ulong,
			     target_ulong, target_ulong) = 
{
    [MTRACE_ENABLE_SET]		= mtrace_enable_set,
    [MTRACE_LABEL_REGISTER] 	= mtrace_label_register,
};

void mtrace_inst_exec(target_ulong a0, target_ulong a1, 
		      target_ulong a2, target_ulong a3,
		      target_ulong a4, target_ulong a5)
{
    if (a0 >= sizeof(mtrace_call) / sizeof(mtrace_call[0]) ||
	mtrace_call[a0] == NULL) 
    {
	fprintf(stderr, "mtrace_inst_exec: bad call %lu\n", a0);
	exit(1);
    }
    
    mtrace_call[a0](a1, a2, a3, a4, a5);
}
