#include <map>

//
// Different objects that share a cache line and cause coherence misses
//
class FalseSharing : public EntryHandler {
public:
	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_access_entry *a = &entry->access;

		list<MtraceObject> objs;

		if (!mtrace_enable.access.value)
			return;
		objs = mtrace_label_map.objects_on_cline(a->guest_addr);
		if (objs.size() > 1) {
			auto it = objs.begin();
			for (; it != objs.end(); ++it)
				false_sharing_at_[a->pc].insert(it->name_);
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
				str_list->append(*sit);
			}
			dict->put("types", str_list);

			list->append(dict);
		}
		json_file->put("false-sharing", list);
	}

private:
	map<pc_t, set<string> > false_sharing_at_;
};
