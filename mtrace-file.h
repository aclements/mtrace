#ifndef _MTRACE_FILE_H_
#define _MTRACE_FILE_H_

#include <stdint.h>

typedef enum {
    mtrace_entry_label = 1,
    mtrace_entry_access,
    mtrace_entry_enable,
    mtrace_entry_fcall,
    mtrace_entry_segment,
} mtrace_entry_t;

#define __pack__ __attribute__((__packed__))

/*
 * The guest specified a segment for a label/object type
 */
struct mtrace_segment_entry {
    mtrace_entry_t type;    
    uint64_t access_count;

    uint64_t baseaddr;
    uint64_t endaddr;
    mtrace_label_t object_type;
    uint16_t cpu;
} __pack__;

/*
 * The guest specified the begining or end to a function call
 */
struct mtrace_fcall_entry {
    mtrace_entry_t type;    
    uint64_t access_count;

    uint16_t cpu;
    uint64_t tid;
    uint64_t pc;
    uint64_t tag;
    uint16_t depth;
    uint8_t end;
} __pack__;

/*
 * The guest enabled/disabled mtrace and specified an optional string
 */
struct mtrace_enable_entry {
    mtrace_entry_t type;
    uint64_t access_count;

    uint8_t enable;
    char str[32];
} __pack__;

/* 
 * The guest specified an string to associate with the range: 
 *   [host_addr, host_addr + bytes)
 */
struct mtrace_label_entry {
    mtrace_entry_t type;
    uint64_t access_count;

    mtrace_label_t label_type;  /* See mtrace-magic.h */
    char str[32];
    uint64_t host_addr;
    uint64_t guest_addr;
    uint64_t bytes;
}__pack_;

/*
 * A memory access to host_addr, executed on cpu, at the guest pc
 */
typedef enum {
    mtrace_access_ld = 1,
    mtrace_access_st,
    mtrace_access_iw,	/* IO Write, which is actually to RAM */
} mtrace_access_t;

struct mtrace_access_entry {
    mtrace_entry_t type;
    uint64_t access_count;

    mtrace_access_t access_type;
    uint16_t cpu;
    uint64_t pc;
    uint64_t host_addr;
    uint64_t guest_addr;
}__pack__;

union mtrace_entry {
    mtrace_entry_t type;

    struct mtrace_access_entry access;
    struct mtrace_label_entry label;
    struct mtrace_enable_entry enable;
    struct mtrace_fcall_entry fcall;
    struct mtrace_segment_entry seg;
}__pack__;

#endif
