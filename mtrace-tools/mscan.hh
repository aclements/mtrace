#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#include <map>

using namespace::std;

#define MAX_CPUS 4

typedef uint64_t call_tag_t;
typedef uint64_t pc_t;
typedef uint64_t timestamp_t;
typedef uint64_t object_id_t;
typedef uint64_t guest_addr_t;

class EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {}
	virtual void exit(void) {}
private:
};

struct MtraceSummary {
	uint64_t app_ops;
};

struct MtraceObject {
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

//
// A bunch of global state the default handlers update
//

// The last mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;
extern Addr2line *addr2line;
extern char mtrace_app_name[32];
extern MtraceSummary mtrace_summary;
extern pc_t mtrace_call_pc[MAX_CPUS];
extern MtraceLabelMap mtrace_label_map;

#endif // _MSCAN_HH_
