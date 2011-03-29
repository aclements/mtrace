#include <map>
#include <set>

using namespace::std;

class DistinctSyscalls : public EntryHandler {
public:
	virtual void handle(union mtrace_entry *entry) {
		if (entry->h.type == mtrace_entry_access) {
			struct mtrace_access_entry *a = &entry->access;
			if (a->traffic)
				tag_to_distinct_set_[current_].insert(a->guest_addr);
		} else if (entry->h.type == mtrace_entry_access) {
			struct mtrace_fcall_entry *f = &entry->fcall;
			switch (f->state) {
			case mtrace_resume:
				current_ = f->tag;
				break;
			case mtrace_start:
				current_ = f->tag;
				break;
			case mtrace_pause:
				current_ = 0;
				break;
			case mtrace_done: {
				uint64_t n;

				n = tag_to_distinct_set_[current_].size();
				tag_to_distinct_set_.erase(current_);
				pc_to_stats_[current_].distinct += n;
				pc_to_stats_[current_].calls++;
				
				current_ = 0;
				break;
			}
			default:
				die("DistinctSyscalls::handle: default error");
			}
		}
		return;
	}

private:
	struct SysStats {
		uint64_t distinct;
		uint64_t calls;
	};

	map<uint64_t, SysStats> pc_to_stats_;
	map<uint64_t, set<uint64_t> > tag_to_distinct_set_;

	// The current tag
	uint64_t current_;
};
