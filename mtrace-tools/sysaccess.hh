#include <map>
#include <vector>

#include "json.hh"

using namespace::std;

//
// Every access per system call
//
class SyscallAccesses : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		struct mtrace_access_entry *cp;
		int cpu;

		if (mtrace_enable.access.value == 0)
			return;
		if (entry->h.type != mtrace_entry_access)
			return;

		cpu = entry->h.cpu;

		cp = (struct mtrace_access_entry *)malloc(sizeof(*cp));
		memcpy(cp, entry, sizeof(*cp));
		pc_to_stats_[mtrace_call_pc[cpu]].push_back(cp);
	}

	virtual void exit(JsonDict *json_file) {
		JsonDict *dict = JsonDict::create();

		auto it = pc_to_stats_.begin();
		for (; it != pc_to_stats_.end(); ++it) {
			JsonList *list;
			char *func;
			char *file;
			int line;
			char name[32];
			uint64_t pc;

			list = JsonList::create();

			pc = it->first;
			if (pc == 0)
				strcpy(name, "(unknown)");
			else if (addr2line->lookup(pc, &func, &file, &line) == 0) {
				strcpy(name, func);
				free(func);
				free(file);
			} else {
				snprintf(name, sizeof(name), "%lx", pc);
			}
			
			auto vit = it->second.begin();
			for (; vit != it->second.end(); ++vit) {
				JsonDict *entry = JsonDict::create();
				entry->put("pc", new JsonHex((*vit)->pc));
				entry->put("guest_addr", new JsonHex((*vit)->guest_addr));
				entry->put("traffic", (*vit)->traffic);
				entry->put("lock", (*vit)->lock);
				entry->put("access_type", (*vit)->access_type == mtrace_access_ld ? "ld" : "st");
				list->append(entry);
			}
			
			dict->put(name, list);
		}

		json_file->put("syscall-accesses", dict);
	}

private:

	map<uint64_t, vector<struct mtrace_access_entry *> > pc_to_stats_;
};
