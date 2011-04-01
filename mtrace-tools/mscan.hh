#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#define MAX_CPUS 4

class EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {}
	virtual void exit(void) {}
private:
};

struct MtraceSummary {
	uint64_t app_ops;
};

typedef uint64_t call_tag_t;
typedef uint64_t pc_t;
typedef uint64_t timestamp_t;

//
// A bunch of global state the default handlers update
//

// The last mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;
extern Addr2line *addr2line;
extern char mtrace_app_name[32];
extern MtraceSummary mtrace_summary;
extern pc_t mtrace_call_pc[MAX_CPUS];

#endif // _MSCAN_HH_
