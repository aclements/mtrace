#ifndef _MTRACE_MAGIC_H_
#define _MTRACE_MAGIC_H_

enum {
    MTRACE_ENABLE_SET = 1,
    MTRACE_LABEL_REGISTER,
};

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

static inline void mtrace_enable_set(unsigned long b)
{
    mtrace_magic(MTRACE_ENABLE_SET, b, 0, 0, 0, 0);
}

static inline void mtrace_label_register(const void * addr, 
					 unsigned long bytes, 
					 const char *str, 
					 unsigned long n)
{
    mtrace_magic(MTRACE_LABEL_REGISTER, (unsigned long)addr, bytes, 
		 (unsigned long)str, n, 0);
}

#endif /* QEMU_MTRACE */
#endif /* _MTRACE_MAGIC_H_ */
