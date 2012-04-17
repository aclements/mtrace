#ifndef _MTRACE_MAGIC_H_
#define _MTRACE_MAGIC_H_

enum {
    MTRACE_ENTRY_REGISTER = 1,
};

typedef enum {
    mtrace_entry_label = 1,
    mtrace_entry_access,
    mtrace_entry_host,
    mtrace_entry_fcall,
    mtrace_entry_segment,
    mtrace_entry_call,
    mtrace_entry_lock,
    mtrace_entry_task,
    mtrace_entry_sched,
    mtrace_entry_machine,
    mtrace_entry_appdata,
    
    mtrace_entry_ascope,        /* abstract variable scope */
    mtrace_entry_avar,          /* abstract variables */

    mtrace_entry_num		/* NB actually num + 1 */
} mtrace_entry_t;

typedef enum {
    mtrace_label_heap = 1,	/* kmalloc, etc */
    mtrace_label_block,		/* page_alloc, etc */
    mtrace_label_static,	/* .data, .bss, etc */
    mtrace_label_percpu,	/* .data..percpu (base addr. set at runtime) */

    mtrace_label_end
} mtrace_label_t;

typedef enum {
    mtrace_access_all_cpu = 1,
    
    mtrace_call_clear_cpu,
    mtrace_call_set_cpu,

    mtrace_disable_count_cpu,
    mtrace_enable_count_cpu,
} mtrace_host_t;

typedef enum {
    /* Don't record accesses. */
    mtrace_record_disable = 0,

    /* Record accesses that cause cache line movement.  Initially, all
     * cache lines will be considered shared by all CPUs. */
    mtrace_record_movement,

    /* Record unique accesses within each abstract scope at a
       granularity of 16 bytes. */
    mtrace_record_ascope,
} mtrace_record_mode_t;

#define __pack__ __attribute__((__packed__))

/*
 * The common mtrace entry header
 */
struct mtrace_entry_header {
    mtrace_entry_t type;
    uint16_t size;
    uint16_t cpu;
    uint64_t access_count;
    uint64_t ts;		/* per-core time stamp */
} __pack__;

/*
 * The guest specified a segment for a label/object type
 */
struct mtrace_segment_entry {
    struct mtrace_entry_header h;    

    uint64_t baseaddr;
    uint64_t endaddr;
    uint16_t cpu;
    mtrace_label_t object_type;
} __pack__;

/*
 * The guest specified the begining or end to a function call
 */
typedef enum {
    /* Start a new call stack at with the function at 'pc', identified
     * by a unique tag.  A given tid may have nested call stacks
     * (e.g., during interrupt handling) and this nesting level is
     * recorded in 'depth'.  Subsequent call_entries with the same cpu
     * apply to this call stack. */
    mtrace_start = 1,
    /* Terminate the call stack identified by 'tag'. */
    mtrace_done,
    /* Resume execution on the paused call stack identified by 'tag'.
     * A call stack may be resumed on a different cpu than it was
     * paused on. */
    mtrace_resume,
    /* Pause execution on the call stack identified by 'tag'.  This is
     * typically done just before starting a new call stack or
     * resuming another call stack. */
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
 * The guest sent a message to the host (QEMU)
 */
struct mtrace_host_entry {
    struct mtrace_entry_header h;
    mtrace_host_t host_type;
    uint64_t global_ts;		/* global time stamp */
    
    union {
	/* Enable/disable access tracing */
	struct {
	    /* Access recording mode */
	    mtrace_record_mode_t mode;
	    /* Name of trace */
	    char str[64];
	} access;

	/* Enable/disable call/ret tracing */
	struct {
	    uint64_t cpu;
	} call;
    };
} __pack__;

/* 
 * The guest specified an string to associate with the range: 
 *   [host_addr, host_addr + bytes)
 */
struct mtrace_label_entry {
    struct mtrace_entry_header h;

    uint64_t host_addr;

    mtrace_label_t label_type;  /* See mtrace-magic.h */
    char str[64];
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
    uint8_t traffic:1;
    uint8_t lock:1;
    uint64_t pc;
    uint64_t host_addr;
    uint64_t guest_addr;
    uint8_t bytes;
}__pack__;

/*
 * A guest lock acquire/release
 */
typedef enum {
    mtrace_lockop_acquire = 1,
    mtrace_lockop_acquired,
    mtrace_lockop_release,
} mtrace_lockop_t;

struct mtrace_lock_entry {
    struct mtrace_entry_header h;

    uint64_t pc;
    uint64_t lock;
    char str[64];
    mtrace_lockop_t op;
    uint8_t read;
} __pack__;

/*
 * A guest task create
 */
typedef enum {
    mtrace_task_init = 1,
    mtrace_task_update,
    mtrace_task_exit,	/* IO Write, which is actually to RAM */
} mtrace_task_t;

struct mtrace_task_entry {
    struct mtrace_entry_header h;

    uint64_t tid;	       /* Thread ID */
    uint64_t tgid;	       /* Thread Group ID */
    mtrace_task_t task_type;
    char str[64];
} __pack__;

/*
 * A task switch in the guest
 */
struct mtrace_sched_entry {
    struct mtrace_entry_header h;

    uint64_t tid;
} __pack__;;

/*
 * The QEMU guest machine info
 */
struct mtrace_machine_entry {
    struct mtrace_entry_header h;

    uint16_t num_cpus;
    uint64_t num_ram;
    uint64_t quantum;
    uint64_t sample;
    uint8_t  locked:1;
    uint8_t  calls:1;
} __pack__;

/*
 * Application defined data
 */
struct mtrace_appdata_entry {
    struct mtrace_entry_header h;
    
    uint16_t appdata_type;
    union {
	uint64_t u64;
    };
} __pack__;


/*
 * Abstract variable scope entry/exit.  Note that abstract variable
 * scopes live on the same call stacks that regular function calls do.
 */
struct mtrace_ascope_entry {
    struct mtrace_entry_header h;
    uint8_t exit:1;
    char name[64];
} __pack__;

/*
 * Abstract variable read/write
 */
struct mtrace_avar_entry {
    struct mtrace_entry_header h;
    uint8_t write:1;
    char name[64];
} __pack__;


union mtrace_entry {
    struct mtrace_entry_header h;

    struct mtrace_access_entry access;
    struct mtrace_label_entry label;
    struct mtrace_host_entry host;
    struct mtrace_fcall_entry fcall;
    struct mtrace_segment_entry seg;
    struct mtrace_call_entry call;
    struct mtrace_lock_entry lock;
    struct mtrace_task_entry task;
    struct mtrace_sched_entry sched;
    struct mtrace_machine_entry machine;
    struct mtrace_appdata_entry appdata;
    struct mtrace_ascope_entry ascope;
    struct mtrace_avar_entry avar;
} __pack__;

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

static inline void mtrace_entry_register(volatile struct mtrace_entry_header *h,
					 unsigned long type,
					 unsigned long len)
{
    mtrace_magic(MTRACE_ENTRY_REGISTER, (unsigned long)h,
		 type, len, 0, 0);
}

static inline void mtrace_enable_set(mtrace_record_mode_t mode, const char *str)
{
    volatile struct mtrace_host_entry entry;

    entry.host_type = mtrace_access_all_cpu;
    entry.access.mode = mode;
    strncpy((char*)entry.access.str, str, sizeof(entry.access.str));
    entry.access.str[sizeof(entry.access.str) - 1] = 0;

    mtrace_entry_register(&entry.h, mtrace_entry_host, sizeof(entry));
}

static inline void mtrace_call_set(unsigned long b, uint64_t cpu)
{
    volatile struct mtrace_host_entry entry;

    entry.host_type = b ? mtrace_call_set_cpu : mtrace_call_clear_cpu;
    entry.call.cpu = cpu;

    mtrace_entry_register(&entry.h, mtrace_entry_host, sizeof(entry));
}

static inline void mtrace_enable_count(void)
{
    volatile struct mtrace_host_entry entry;

    entry.host_type = mtrace_enable_count_cpu;
    mtrace_entry_register(&entry.h, mtrace_entry_host, sizeof(entry));
}

static inline void mtrace_disable_count(void)
{
    volatile struct mtrace_host_entry entry;

    entry.host_type = mtrace_disable_count_cpu;
    mtrace_entry_register(&entry.h, mtrace_entry_host, sizeof(entry));
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
    label.guest_addr = (uintptr_t)addr;
    label.bytes = bytes;
    label.pc = call_site;

    mtrace_entry_register(&label.h, mtrace_entry_label, sizeof(label));
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
    entry.cpu = cpu;

    mtrace_entry_register(&entry.h, mtrace_entry_segment, sizeof(entry));
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

    mtrace_entry_register(&entry.h, mtrace_entry_fcall, sizeof(entry));
}

static inline void mtrace_lock_register(unsigned long pc,
                                        void *lock,
					const char *str,
					mtrace_lockop_t op,
					unsigned long is_read)
{
    volatile struct mtrace_lock_entry entry;
    entry.pc = pc;
    entry.lock = (unsigned long)lock;
    strncpy((char*)entry.str, str, sizeof(entry.str));
    entry.str[sizeof(entry.str)-1] = 0;
    entry.op = op;
    entry.read = is_read;

    mtrace_entry_register(&entry.h, mtrace_entry_lock, sizeof(entry));
}

static inline void mtrace_task_register(unsigned long tid,
					unsigned long tgid,
					mtrace_task_t type,
					const char *str)
{
    volatile struct mtrace_task_entry entry;
    entry.tid = tid;
    entry.tgid = tgid;
    entry.task_type = type;
    strncpy((char*)entry.str, str, sizeof(entry.str));
    entry.str[sizeof(entry.str) - 1] = 0;

    mtrace_entry_register(&entry.h, mtrace_entry_task, sizeof(entry));
}

static inline void mtrace_sched_record(unsigned long tid)
{
    volatile struct mtrace_sched_entry entry;
    entry.tid = tid;

    mtrace_entry_register(&entry.h, mtrace_entry_sched, sizeof(entry));
}

static inline void mtrace_appdata_register(struct mtrace_appdata_entry *appdata)
{
    volatile struct mtrace_appdata_entry entry;
    memcpy((void *)&entry, appdata, sizeof(entry));

    mtrace_entry_register(&entry.h, mtrace_entry_appdata, sizeof(entry));
}

static inline void mtrace_avar_register(int is_write, const char *avar)
{
    volatile struct mtrace_avar_entry entry;

    entry.write = is_write;
    strncpy((char*)entry.name, avar, sizeof(entry.name));

    mtrace_entry_register(&entry.h, mtrace_entry_avar, sizeof(entry));
}

static inline void mtrace_ascope_register(int is_exit, const char *name)
{
    volatile struct mtrace_ascope_entry entry;

    entry.exit = is_exit;
    strncpy((char*)entry.name, name, sizeof(entry.name));

    mtrace_entry_register(&entry.h, mtrace_entry_ascope, sizeof(entry));
}

#endif /* QEMU_MTRACE */
#endif /* _MTRACE_MAGIC_H_ */
