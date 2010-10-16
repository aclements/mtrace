#ifndef _MTRACE_FILE_H_
#define _MTRACE_FILE_H_

#include <stdint.h>

struct mtrace_type_entry {
    char str[32];
    uint64_t host_addr;
    uint64_t guest_addr;
    uint64_t bytes;
};

struct mtrace_entry {
    uint8_t type;
    uint16_t cpu;
    uint64_t pc;
    uint64_t host_addr;
    uint64_t guest_addr;
};

#endif
