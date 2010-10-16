#ifndef _MTRACE_MAGIC_H_
#define _MTRACE_MAGIC_H_

enum {
    MTRACE_ENABLE_SET = 1,
};

#ifndef QEMU_MTRACE

/*
 * Magic instruction for calling into mtrace in QEMU.
 */
static inline void mtrace_magic(unsigned long ax, unsigned long bx, 
				unsigned long cx, unsigned long dx)
{
    __asm __volatile(".byte 0xf1" : : "a" (ax), "b" (bx), "c" (cx), "d" (dx));
}

static inline void mtrace_enable_set(unsigned long b)
{
    mtrace_magic(MTRACE_ENABLE_SET, b, 0, 0);
}

#endif /* QEMU_MTRACE */
#endif /* _MTRACE_MAGIC_H_ */
