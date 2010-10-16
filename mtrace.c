/*
 * Memory access tracing/logging
 */

static int mtrace_enable = 0;

static void mtrace_entry(const char *prefix, target_ulong host_addr, 
			target_ulong guest_addr)
{
    if (!mtrace_enable)
	return;

    fprintf(stderr, "%-3s [%-3u %016lx  %016lx  %016lx]\n", 
	    prefix,
	    cpu_single_env->cpu_index, 
	    cpu_single_env->eip,
	    host_addr, 
	    guest_addr);
}

void mtrace_st(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_entry("S", host_addr, guest_addr);
}

void mtrace_ld(target_ulong host_addr, target_ulong guest_addr)
{
    mtrace_entry("L", host_addr, guest_addr);
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
	mtrace_entry("IW", (unsigned long) 
		    qemu_get_ram_ptr(ram_addr), 
		    guest_addr);
    }
}

void mtrace_io_read(void *cb, target_phys_addr_t ram_addr, target_ulong guest_addr)
{
    /* Nothing to do.. */
}

void mtrace_inst_exec(void)
{
    //fprintf(stderr, "the magic instruction..\n");
    mtrace_enable = !mtrace_enable;
}
