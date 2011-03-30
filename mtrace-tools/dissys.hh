#include <map>
#include <set>

using namespace::std;

class DistinctSyscalls : public EntryHandler {
public:
	virtual void handle(union mtrace_entry *entry) {
		int cpu;

		if (mtrace_enable.access.value == 0)
			return;

		cpu = entry->h.cpu;

		if (entry->h.type == mtrace_entry_access) {
			struct mtrace_access_entry *a = &entry->access;
			if (a->traffic)
				tag_to_distinct_set_[current_[cpu]].insert(a->guest_addr & ~63UL);
		} else if (entry->h.type == mtrace_entry_fcall) {
			struct mtrace_fcall_entry *f = &entry->fcall;
			
			switch (f->state) {
			case mtrace_resume:
				current_[cpu] = f->tag;
				break;
			case mtrace_start:
				current_[cpu] = f->tag;
				tag_to_pc_[current_[cpu]] = f->pc;
				break;
			case mtrace_pause:
				current_[cpu] = 0;
				break;
			case mtrace_done:
				count_tag(current_[cpu]);
				current_[cpu] = 0;
				break;
			default:
				die("DistinctSyscalls::handle: default error");
			}
		}
		return;
	}

	virtual void exit(mtrace_entry_t type) {
		if (type != mtrace_entry_access)
			return;

		while (tag_to_distinct_set_.size())
			count_tag(tag_to_distinct_set_.begin()->first);

		map<uint64_t, SysStats>::iterator pit = pc_to_stats_.begin();
		for (; pit != pc_to_stats_.end(); ++pit) {
			float n;
			
			n = (float)pit->second.distinct / 
				(float)pit->second.calls;
			printf("%lx %lu %lu %f\n", pit->first, pit->second.calls, pit->second.distinct, n);
		}
	}

private:
	void count_tag(uint64_t tag) {
		uint64_t pc;
		uint64_t n;

		n = tag_to_distinct_set_[tag].size();
		tag_to_distinct_set_.erase(tag);
		pc = tag_to_pc_[tag];
		tag_to_pc_.erase(tag);

		if (pc_to_stats_.find(pc) == pc_to_stats_.end()) {
			pc_to_stats_[pc].distinct = 0;
			pc_to_stats_[pc].calls = 0;
		}
		pc_to_stats_[pc].distinct += n;
		pc_to_stats_[pc].calls++;
	}

	struct SysStats {
		uint64_t distinct;
		uint64_t calls;
	};

	map<uint64_t, uint64_t> tag_to_pc_;
	map<uint64_t, SysStats> pc_to_stats_;
	map<uint64_t, set<uint64_t> > tag_to_distinct_set_;

	// The current tag
	uint64_t current_[MAX_CPUS];
};
