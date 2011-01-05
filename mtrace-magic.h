#ifndef _MTRACE_MAGIC_H_
#define _MTRACE_MAGIC_H_

enum {
    MTRACE_ENABLE_SET = 1,
    MTRACE_ENTRY_REGISTER,
};

typedef enum {
    mtrace_entry_label = 1,
    mtrace_entry_access,
    mtrace_entry_enable,
    mtrace_entry_fcall,
    mtrace_entry_segment,
    mtrace_entry_call,
} mtrace_entry_t;

typedef enum {
    mtrace_label_heap = 1,	/* kmalloc, etc */
    mtrace_label_block,		/* page_alloc, etc */
    mtrace_label_static,	/* .data, .bss, etc */
    mtrace_label_percpu,	/* .data..percpu (base addr. set at runtime) */

    mtrace_label_end
} mtrace_label_t;

#define __pack__ __attribute__((__packed__))

/*
 * The common mtrace entry header
 */
struct mtrace_entry_header {
    mtrace_entry_t type;
    uint16_t size;
    uint16_t cpu;
    uint64_t access_count;
} __pack__;

/*
 * The guest specified a segment for a label/object type
 */
struct mtrace_segment_entry {
    struct mtrace_entry_header h;    

    uint64_t baseaddr;
    uint64_t endaddr;
    mtrace_label_t object_type;
} __pack__;

/*
 * The guest specified the begining or end to a function call
 */
typedef enum {
    mtrace_start = 1,
    mtrace_done,
    mtrace_resume,
    mtrace_pause,
} mtrace_call_state_t;

struct mtrace_fcall_entry {
    struct mtrace_entry_header h;    

    uint64_t tid;
    uint64_t pc;
    uint64_t tag;
    uint16_t depth;
    mtrace_call_state_t state;
} __pack__;

struct mtrace_call_entry {
    struct mtrace_entry_header h;    

    uint64_t target_pc;
    uint64_t return_pc;    
    int ret;
} __pack__;

/*
 * The guest enabled/disabled mtrace and specified an optional string
 */
struct mtrace_enable_entry {
    struct mtrace_entry_header h;

    uint8_t enable;
    char str[32];
} __pack__;

/* 
 * The guest specified an string to associate with the range: 
 *   [host_addr, host_addr + bytes)
 */
struct mtrace_label_entry {
    struct mtrace_entry_header h;

    uint64_t host_addr;

    mtrace_label_t label_type;  /* See mtrace-magic.h */
    char str[32];
    uint64_t guest_addr;
    uint64_t bytes;
    uint64_t pc;
} __pack__;

/*
 * A memory access to host_addr, executed on cpu, at the guest pc
 */
typedef enum {
    mtrace_access_ld = 1,
    mtrace_access_st,
    mtrace_access_iw,	/* IO Write, which is actually to RAM */
} mtrace_access_t;

struct mtrace_access_entry {
    struct mtrace_entry_header h;

    mtrace_access_t access_type;
    uint64_t pc;
    uint64_t host_addr;
    uint64_t guest_addr;
}__pack__;

union mtrace_entry {
    struct mtrace_entry_header h;

    struct mtrace_access_entry access;
    struct mtrace_label_entry label;
    struct mtrace_enable_entry enable;
    struct mtrace_fcall_entry fcall;
    struct mtrace_segment_entry seg;
    struct mtrace_call_entry call;
}__pack__;

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
					 unsigned long n,
					 unsigned long call_site)
{
    volatile struct mtrace_label_entry label;

    if (n >= sizeof(label.str))
	n = sizeof(label.str) - 1;

    label.label_type = type;
    memcpy((void *)label.str, str, n);
    label.str[n] = 0;
    label.guest_addr = (uint64_t)addr;
    label.bytes = bytes;
    label.pc = call_site;

    mtrace_magic(MTRACE_ENTRY_REGISTER, (unsigned long)&label,
		 mtrace_entry_label, sizeof(label), 0, 0);
}

static inline void mtrace_segment_register(unsigned long baseaddr,
					   unsigned long endaddr,
					   mtrace_label_t type,
					   unsigned long cpu)
{
    volatile struct mtrace_segment_entry entry;
    entry.baseaddr = baseaddr;
    entry.endaddr = endaddr;
    entry.object_type = type;
    mtrace_magic(MTRACE_ENTRY_REGISTER, (unsigned long)&entry,
		 mtrace_entry_segment, sizeof(entry), cpu, 0);
}

static inline void mtrace_fcall_register(unsigned long tid,
					 unsigned long pc,
					 unsigned long tag,
					 unsigned int depth,
					 mtrace_call_state_t state)
{
    volatile struct mtrace_fcall_entry entry;
    entry.tid = tid;
    entry.pc = pc;
    entry.tag = tag;
    entry.depth = depth;
    entry.state = state;
    mtrace_magic(MTRACE_ENTRY_REGISTER, (unsigned long)&entry,
		 mtrace_entry_fcall, sizeof(entry), ~0, 0);
}

#endif /* QEMU_MTRACE */
#endif /* _MTRACE_MAGIC_H_ */
