#include <stdint.h>
#include <string.h>

#include <fcntl.h>

#include <map>
#include <list>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
#include "objinfo.h"
}

#include "addr2line.hh"
#include "mscan.hh"
#include "dissys.hh"

using namespace::std;

typedef map<uint64_t, struct mtrace_label_entry> LabelMap;

// A bunch of global state the default handlers update
struct mtrace_host_entry mtrace_enable;
Addr2line *addr2line;

static LabelMap labels;

class DefaultHostHandler : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_host_entry *e = &entry->host;
		if (e->host_type == mtrace_call_clear_cpu ||
		    e->host_type == mtrace_call_set_cpu) 
		 {
			 return;
		 } else if (e->host_type != mtrace_access_all_cpu)
			die("handle_host: unhandled type %u", e->host_type);

		mtrace_enable = *e;
	}
};

static list<EntryHandler *> entry_handler[mtrace_entry_num];

static inline union mtrace_entry * alloc_entry(void)
{
	return (union mtrace_entry *)malloc(sizeof(union mtrace_entry));
}

static inline void free_entry(void *entry)
{
	free(entry);
}

static inline void init_entry_alloc(void)
{
	// nothing
}

static void process_log(gzFile log)
{
	union mtrace_entry entry;
	int i;
	int r;

	printf("Scanning log file ...\n");
	fflush(0);
        while ((r = read_entry(log, &entry)) > 0) {
		list<EntryHandler *> *l = &entry_handler[entry.h.type];
		list<EntryHandler *>::iterator it = l->begin();
		for(; it != l->end(); ++it)
			(*it)->handle(&entry);
	}

	for (i = mtrace_entry_label; i < mtrace_entry_num; i++) {
		list<EntryHandler *> *l = &entry_handler[i];
		list<EntryHandler *>::iterator it = l->begin();
		for(; it != l->end(); ++it) {
			(*it)->exit((mtrace_entry_t)i);
		}
	}
}

static void init_handlers(void)
{
	// The default handler come first
	entry_handler[mtrace_entry_host].push_front(new DefaultHostHandler());

	//
	// Extra handlers come next
	//
	DistinctSyscalls *dissys = new DistinctSyscalls();
	entry_handler[mtrace_entry_access].push_front(dissys);	
	entry_handler[mtrace_entry_fcall].push_front(dissys);	
}

int main(int ac, char **av)
{
	char symFile[128];
	char elfFile[128];
	char logFile[128];
	gzFile log;
	int symFd;

	if (ac != 3)
		die("usage: %s mtrace-dir mtrace-out", av[0]);

	snprintf(logFile, sizeof(logFile), "%s/%s", av[1], av[2]);
	snprintf(symFile, sizeof(symFile), "%s/vmlinux.syms", av[1]);
	snprintf(elfFile, sizeof(elfFile), "%s/vmlinux", av[1]);

        log = gzopen(logFile, "rb");
        if (!log)
		edie("gzopen %s", logFile);
	if ((symFd = open(symFile, O_RDONLY)) < 0)
		edie("open %s", symFile);

	addr2line = new Addr2line(elfFile);

	init_entry_alloc();
	init_handlers();

	process_log(log);

	gzclose(log);
	close(symFd);
	return 0;
}
