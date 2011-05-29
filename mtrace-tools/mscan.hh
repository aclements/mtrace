#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#include <map>
#include <sstream>

#include "addr2line.hh"

using namespace::std;

#define MAX_CPUS 4

typedef uint64_t call_tag_t;
typedef uint64_t pc_t;
typedef uint64_t timestamp_t;
typedef uint64_t object_id_t;
typedef uint64_t guest_addr_t;

class JsonDict;

class EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {}
	virtual void exit(void) {}
	virtual void exit(JsonDict *json_file) {}
private:
};

struct MtraceSummary {
	uint64_t app_ops;
	char app_name[32];
};

struct MtraceObject {
	MtraceObject(void) {}

	MtraceObject(object_id_t id, const struct mtrace_label_entry *l) {
		id_ = id;
		guest_addr_ = l->guest_addr;
	}

	object_id_t id_;
	guest_addr_t guest_addr_;
};

class MtraceLabelMap {
public:
	void add_label(const struct mtrace_label_entry *l) {
		static uint64_t object_count;
		object_id_t id;
		
		if (l->label_type == 0 || l->label_type >= mtrace_label_end)
			die("MtraceLabelMap::add_label: bad type: %u", l->label_type);

		if (object_.find(l->guest_addr) != object_.end())
			die("MtraceLabelMap::add_label: overlapping labels");
		
		// XXX ignore for now
		if (l->label_type == mtrace_label_block)
			return;
		
		id = ++object_count;
		MtraceObject o(id, l);

		object_.insert(pair<guest_addr_t, MtraceObject>(l->guest_addr, o));
	}

	void rem_label(const struct mtrace_label_entry *l) {
		static uint64_t misses[mtrace_label_end];

		// XXX ignore for now
		if (l->label_type == mtrace_label_block)
			return;

		auto it = object_.find(l->guest_addr);
		if (it == object_.end()) {
			extern struct mtrace_host_entry mtrace_enable;

			if (mtrace_enable.access.value)
				die("miss while mtrace enabled");

			// We tolerate a few kfree calls for which we haven't
			// seen a previous kmalloc, because we might have missed
			// the kmalloc before the mtrace kernel code registered
			// the trace functions.
			misses[l->label_type]++;
			if (misses[l->label_type] > 200)
				die("suspicious number of misses %u", 
				    l->label_type);
		} else {
			object_.erase(it);
		}
	}

	bool lower_bound(guest_addr_t addr, MtraceObject *ret) const {
		auto it = object_.lower_bound(addr);
		if (it == object_.end())
			return false;
		
		memcpy(ret, &it->second, sizeof(*ret));
		return true;
	}

private:
	map<guest_addr_t, MtraceObject> object_;
};

class MtraceAddr2line{
public:
	MtraceAddr2line(const char *elf_file)
		: addr2line_(elf_file) {}

	string function_name(pc_t pc) {
		string func;
		string file;
		string line;

		all_string(pc, func, file, line);
		return func;
	}
	
	string function_description(pc_t pc) {
		string func;
		string file;
		string line;

		all_string(pc, func, file, line);
		return file + ":" + line + ":" + func;
	}

private:
	void all_string(pc_t pc, string &func, string &file, string &line) {
		char *xfunc;
		char *xfile;
		int xline;
		
		if (pc == 0) {
			func = "(unknown function)";
			file = "(unknown file)";
			line = "0";
		} else if (addr2line_.lookup(pc, &xfunc, &xfile, &xline) == 0) {
			stringstream ss;

			func = xfunc;
			file = xfile;
			ss << xline;
			line = ss.str();
			
			free(xfunc);
			free(xfile);
			
		} else {
			stringstream ss;

			ss << pc;
			func = ss.str();
			file = "(unknown file)";
			line = "0";
		}
	}
	
	
	Addr2line addr2line_;
};

//
// A bunch of global state the default handlers update
//

// The last mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;
// An addr2line instance for the ELF file
extern MtraceAddr2line *addr2line;
// A summary of the application/workload
extern MtraceSummary mtrace_summary;
// The current fcall/kernel entry point
extern pc_t mtrace_call_pc[MAX_CPUS];
// A map from guest address to kernel object
extern MtraceLabelMap mtrace_label_map;

#endif // _MSCAN_HH_
