#include <map>

//
// Different objects that share a cache line and cause coherence misses
//
class FalseSharing : public EntryHandler {
	struct FalseSharingInstance {
		FalseSharingInstance(pc_t alloc_pc, string name)
			: alloc_pc_(alloc_pc), name_(name) {}
		pc_t alloc_pc_;
		string name_;
	};

public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_access_entry *a = &entry->access;

		list<MtraceObject> objs;

		if (!mtrace_enable.access.value)
			return;
		objs = mtrace_label_map.objects_on_cline(a->guest_addr);
		if (objs.size() > 1) {
			auto it = objs.begin();
			for (; it != objs.end(); ++it) {
				FalseSharingInstance fsi(it->alloc_pc_, it->name_);
				false_sharing_at_[a->pc].insert(fsi);
			}
		}
	}

	virtual void exit(JsonDict *json_file) {
		JsonList *list = JsonList::create();

		auto it = false_sharing_at_.begin();
		for (; it != false_sharing_at_.end(); ++it) {
			JsonDict *dict = JsonDict::create();

			dict->put("pc", new JsonHex(it->first));

			JsonList *str_list = JsonList::create();
			auto sit = it->second.begin();
			for (; sit != it->second.end(); ++sit) {
				str_list->append(sit->name_);
			}
			dict->put("types", str_list);

			list->append(dict);
		}
		json_file->put("false-sharing", list);
	}

private:
	struct LtFalse
	{
		bool operator()(FalseSharingInstance x0, FalseSharingInstance x1) const {
			if (x0.name_ == x1.name_)
				return x0.alloc_pc_ < x1.alloc_pc_;
			return x0.name_ < x1.name_;
		}
	};

	map<pc_t, set<FalseSharingInstance, LtFalse> > false_sharing_at_;
};
