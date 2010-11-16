#ifndef _MTRACE_MAGIC_H_
#define _MTRACE_MAGIC_H_

enum {
    MTRACE_ENABLE_SET = 1,
    MTRACE_LABEL_REGISTER,
    MTRACE_FCALL_REGISTER,
    MTRACE_SEGMENT_REGISTER,
};

typedef enum {
    mtrace_label_heap = 1,	/* kmalloc, etc */
    mtrace_label_block,		/* page_alloc, etc */
    mtrace_label_static,	/* .data, .bss, etc */
    mtrace_label_percpu,	/* .data..percpu (base addr. set at runtime) */

    mtrace_label_end
} mtrace_label_t;

#ifndef QEMU_MTRACE

/*
 * Magic instruction for calling into mtrace in QEMU.
 */
static inline void mtrace_magic(unsigned long ax, unsigned long bx, 
				unsigned long cx, unsigned long dx,
				unsigned long si, unsigned long di)
{
    __asm __volatile("xchg %%bx, %%bx" 
		     : 
		     : "a" (ax), "b" (bx), 
		       "c" (cx), "d" (dx), 
		       "S" (si), "D" (di));
}

static inline void mtrace_enable_set(unsigned long b, const char *str, 
				     unsigned long n)
{
    mtrace_magic(MTRACE_ENABLE_SET, b, (unsigned long)str, n, 0, 0);
}

static inline void mtrace_label_register(mtrace_label_t type,
					 const void * addr, 
					 unsigned long bytes, 
					 const char *str, 
					 unsigned long n)
{
    mtrace_magic(MTRACE_LABEL_REGISTER, (unsigned long) type, 
		 (unsigned long)addr, bytes, (unsigned long)str, n);
}

static inline void mtrace_fcall_register(unsigned long tid,
					 unsigned long pc,
					 unsigned long tag,
					 unsigned int depth,
					 int end)
{
    mtrace_magic(MTRACE_FCALL_REGISTER, tid, pc, tag, depth, end);
}

static inline void mtrace_segment_register(unsigned long baseaddr,
					   unsigned long endaddr,
					   mtrace_label_t type,
					   unsigned long cpu)
{
    mtrace_magic(MTRACE_SEGMENT_REGISTER, baseaddr, endaddr, type, cpu, 0);    
}

#endif /* QEMU_MTRACE */
#endif /* _MTRACE_MAGIC_H_ */
