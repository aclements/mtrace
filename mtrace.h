#ifndef _MTRACE_H_
#define _MTRACE_H_

/* mtrace.c */
void mtrace_init(void);

uint8_t *mtrace_cline_track_alloc(size_t bytes);
void mtrace_cline_track_free(uint8_t *cline_track);

void mtrace_log_file_set(const char *path);
void mtrace_system_enable_set(int b);
int  mtrace_system_enable_get(void);
void mtrace_cline_trace_set(int b);
void mtrace_call_trace_set(int b);
void mtrace_sample_set(int n);

void mtrace_exec_start(CPUState *env);
void mtrace_exec_stop(CPUState *env);

#endif
