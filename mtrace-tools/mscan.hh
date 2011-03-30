#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#define MAX_CPUS 4

class EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {}
	virtual void exit(void) {}
private:
};

//
// A bunch of global state the default handlers update
//

// The last mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;
extern Addr2line *addr2line;

#endif // _MSCAN_HH_
