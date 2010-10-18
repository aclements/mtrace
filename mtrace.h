#ifndef _MTRACE_H_
#define _MTRACE_H_

/* mtrace.c */
void mtrace_format_set(const char *id);
void mtrace_log_file_set(const char *path);
void mtrace_init(void);
int  mtrace_cline_track(void);
uint8_t *mtrace_cline_track_alloc(size_t bytes);
void mtrace_cline_track_free(uint8_t *cline_track);

#endif
