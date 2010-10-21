#ifndef _MTRACE_FILE_H_
#define _MTRACE_FILE_H_

#include <stdint.h>

typedef enum {
    mtrace_access_ld = 1,
    mtrace_access_st,
    mtrace_access_iw,	/* IO Write, which is actually to RAM */
} mtrace_access_t;

typedef enum {
    mtrace_entry_label = 1,
    mtrace_entry_access,
} mtrace_entry_t;

/* 
 * The guest specified an string to associate with the range: 
 *   [host_addr, host_addr + bytes)
 */
struct mtrace_label_entry {
    mtrace_entry_t type;

    char str[32];
    uint64_t host_addr;
    uint64_t guest_addr;
    uint64_t bytes;
};

/*
 * A memory access to host_addr, executed on cpu, at the guest pc
 */
struct mtrace_access_entry {
    mtrace_entry_t type;

    mtrace_access_t access_type;
    uint64_t access_count;
    uint16_t cpu;
    uint64_t pc;
    uint64_t host_addr;
    uint64_t guest_addr;
};

union mtrace_entry {
    mtrace_entry_t type;

    struct mtrace_access_entry access;
    struct mtrace_label_entry label;
};

#endif
