#ifndef _MTRACE_H_
#define _MTRACE_H_

struct RAMBlock;

/* mtrace.c */
void mtrace_init(void);

void mtrace_cline_track_free(struct RAMBlock *block);

void mtrace_log_file_set(const char *path);
void mtrace_system_enable_set(int b);
int  mtrace_system_enable_get(void);
void mtrace_cline_trace_set(int b);
void mtrace_call_trace_set(int b);
void mtrace_lock_trace_set(int b);
void mtrace_sample_set(int n);
int  mtrace_enable_get(void);
void mtrace_quantum_set(int n);
int  mtrace_quantum_get(void);

#endif
