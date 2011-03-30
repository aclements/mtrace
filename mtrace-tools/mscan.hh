#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#define MAX_CPUS 4

class EntryHandler {
public:
	virtual void handle(union mtrace_entry *entry) = 0;
	virtual void exit(mtrace_entry_t type) {}
private:
};

//
// A bunch of global state the default handlers update
//

// The last mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;

#endif // _MSCAN_HH_
