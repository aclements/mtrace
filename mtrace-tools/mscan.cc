#include <stdint.h>
#include <string.h>

#include <fcntl.h>

#include <map>
#include <list>
#include <iostream>
#include <fstream>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}

#include "addr2line.hh"
#include "mscan.hh"
#include "dissys.hh"
#include "sersec.hh"
#include "sysaccess.hh"
#include "false.hh"

extern "C" ssize_t getline(char **lineptr, size_t *n, FILE *stream);

using namespace::std;

typedef map<uint64_t, struct mtrace_label_entry> LabelMap;

// A bunch of global state the default handlers update
struct mtrace_host_entry mtrace_enable;
MtraceAddr2line *addr2line;
MtraceSummary mtrace_summary;
pc_t mtrace_call_pc[MAX_CPUS];
MtraceLabelMap mtrace_label_map;

static LabelMap labels;
static list<struct mtrace_label_entry> percpu_labels;

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

		if (!mtrace_summary.app_name[0])
			strncpy(mtrace_summary.app_name, e->access.str,
				sizeof(mtrace_summary.app_name));
		mtrace_enable = *e;
	}
};

class DefaultAppDataHandler : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_appdata_entry *a = &entry->appdata;
		mtrace_summary.app_ops = a->u64;
	}
};

class DefaultMachineHandler : public EntryHandler {
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_machine_entry *m = &entry->machine;
		mtrace_summary.num_cpus = m->num_cpus;
		mtrace_summary.num_ram = m->num_ram;
	}
};

class DefaultFcallHandler : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_fcall_entry *f = &entry->fcall;
		int cpu = f->h.cpu;

		switch (f->state) {
		case mtrace_resume:
			mtrace_call_pc[cpu] = f->pc;
			break;
		case mtrace_start:
			mtrace_call_pc[cpu] = f->pc;
			break;
		case mtrace_pause:
			mtrace_call_pc[cpu] = 0;
			break;
		case mtrace_done:
			mtrace_call_pc[cpu] = 0;
			break;
		default:
			die("DefaultFcallHandler::handle: default error");
		}
	}
};

class DefaultLabelHandler : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_label_entry *l = &entry->label;

		if (l->label_type == 0 || l->label_type >= mtrace_label_end)
			die("DefaultLabelHandler::handle: bad label type: %u", l->label_type);

		if (l->bytes)
			mtrace_label_map.add_label(l);
		else
			mtrace_label_map.rem_label(l);
	}
};

class DefaultSegmentHandler : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_segment_entry *s = &entry->seg;

		if (s->object_type != mtrace_label_percpu)
			die("DefaultSegmentHandler::handle: bad type %u", s->object_type);

		auto it = percpu_labels.begin();
		for (; it != percpu_labels.end(); ++it) {
			struct mtrace_label_entry offset = *it;
			struct mtrace_label_entry l;

			memcpy(&l, &offset, sizeof(l));
			l.guest_addr = s->baseaddr + offset.guest_addr;
			l.label_type = mtrace_label_percpu;

			if (l.guest_addr + l.bytes > s->endaddr)
				die("DefaultSegmentHandler::handle: bad label %s", l.str);

			mtrace_label_map.add_label(&l);
		}

		// XXX Oops, we leak the mtrace_label_entry in percpu_labels after
		// we handle the final segment.
	}
};

static list<EntryHandler *> entry_handler[mtrace_entry_num];
static list<EntryHandler *> exit_handler;

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
	int r;

	fflush(0);
        while ((r = read_entry(log, &entry)) > 0) {
		list<EntryHandler *> *l = &entry_handler[entry.h.type];
		list<EntryHandler *>::iterator it = l->begin();
		for(; it != l->end(); ++it)
			(*it)->handle(&entry);
	}

	JsonDict *json_dict = JsonDict::create();;

	list<EntryHandler *>::iterator it = exit_handler.begin();
	for(; it != exit_handler.end(); ++it)
	    (*it)->exit(json_dict);

	cout << json_dict->str(0) << "\n";
	delete json_dict;
}

static void init_handlers(void)
{
	//
	// The default handler come first
	//
	entry_handler[mtrace_entry_host].push_front(new DefaultHostHandler());
	entry_handler[mtrace_entry_appdata].push_front(new DefaultAppDataHandler());
	entry_handler[mtrace_entry_fcall].push_front(new DefaultFcallHandler());
	entry_handler[mtrace_entry_label].push_front(new DefaultLabelHandler());
	entry_handler[mtrace_entry_segment].push_front(new DefaultSegmentHandler());
	entry_handler[mtrace_entry_machine].push_front(new DefaultMachineHandler());

	//
	// Extra handlers come next
	//
	DistinctSyscalls *dissys = new DistinctSyscalls();
	entry_handler[mtrace_entry_access].push_back(dissys);
	entry_handler[mtrace_entry_fcall].push_back(dissys);
	exit_handler.push_back(dissys);

	DistinctOps *disops = new DistinctOps(dissys);
	exit_handler.push_back(disops);

	SerialSections *sersecs = new SerialSections();
	entry_handler[mtrace_entry_lock].push_back(sersecs);
	entry_handler[mtrace_entry_access].push_back(sersecs);
	exit_handler.push_back(sersecs);

	FalseSharing *false_sharing = new FalseSharing();
	entry_handler[mtrace_entry_access].push_back(false_sharing);
	exit_handler.push_back(false_sharing);

#if 0
	SyscallAccesses *sysaccesses = new SyscallAccesses();
	entry_handler[mtrace_entry_access].push_back(sysaccesses);
	exit_handler.push_back(sysaccesses);

	SyscallAccessesPC *sys_accesses_pc = new SyscallAccessesPC(sysaccesses);
	exit_handler.push_back(sys_accesses_pc);
#endif
}

static void init_static_syms(const char *sym_file)
{
	list<struct mtrace_label_entry> tmp;
	uint64_t percpu_start = 0;
	uint64_t percpu_end = 0;
	char line[256];
	uint64_t addr;
	uint64_t size;
	char str[128];
	char type;
	int r;

	ifstream fi;
	fi.open(sym_file);
	if (fi.fail())
	    die("failed to open %s", sym_file);

	while (fi.good()) {
		fi.getline(line, sizeof(line));

		r = sscanf(line, "%lx %lx %c %s", &addr, &size, &type, &str);
		if (r == 4 && (type == 'D' || type == 'd' || // .data
			       type == 'B' || type == 'b' || // .bbs
			       type == 'r' || type == 'R' || // .ro
			       type == 'A'))  	      	     // absolute
		{
			struct mtrace_label_entry l;

			l.h.type = mtrace_entry_label;
			l.h.access_count = 0;
			l.label_type = mtrace_label_static;
			strncpy(l.str, str, sizeof(l.str) - 1);
			l.str[sizeof(l.str) - 1] = 0;
			l.host_addr = 0;
			l.guest_addr = addr;
			l.bytes = size;

			tmp.push_back(l);
			continue;
		}

		r = sscanf(line, "%lx %c %s", &addr, &type, &str);
		if (r == 3 && type == 'D') {
			if (!strcmp("__per_cpu_end", str)) {
				percpu_end = addr;
			} else if (!strcmp("__per_cpu_start", str)) {
				percpu_start = addr;
			}
			continue;
		}
	}

	// Move all the labels for percpu variables from the mtrace_label_static
	// list to the temporary list.  Once we know each CPUs percpu base
	// address we add percpu objects onto the mtrace_label_percpu list.
	while (tmp.size()) {
		auto it = tmp.begin();
		struct mtrace_label_entry l = *it;

		if (percpu_start <= l.guest_addr && l.guest_addr < percpu_end)
			percpu_labels.push_back(l);
		else
			mtrace_label_map.add_label(&l);

		tmp.erase(it);
	}

	fi.close();
}

int main(int ac, char **av)
{
	char sym_file[128] = "mscan.syms";
	char elf_file[128] = "mscan.kern";
	char log_file[128] = "mtrace.out";
	gzFile log;

        log = gzopen(log_file, "rb");
        if (!log)
		edie("gzopen %s", log_file);

	addr2line = new MtraceAddr2line(elf_file);

	init_static_syms(sym_file);
	init_entry_alloc();
	init_handlers();

	process_log(log);

	gzclose(log);
	return 0;
}
