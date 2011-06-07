#include <ext/hash_map>
#include <assert.h>
#include <cinttypes>

#include "json.hh"
#include "hash.h"

using namespace::std;
using namespace::__gnu_cxx;

//
// Handle OS X:
//  * uint64_t is a long long unsigned int 
//  * there is no hash<long long unsigned int>
//
namespace __gnu_cxx {
template <>
struct hash<long long unsigned int> {
	size_t operator()(long long unsigned int k) const
	{
		// XXX should be a static assertion		
		assert(sizeof(k) / sizeof(uintptr_t));
		return bb_hash((uintptr_t *)&k, sizeof(k) / sizeof(uintptr_t));
	}
};
}

struct SerialSection {
	SerialSection(void)
		: start(0), 
		  end(0), 
		  acquire_cpu(0), 
		  release_cpu(0), 
		  call_pc(0), 
		  acquire_pc(0), 
		  per_pc_coherence_miss(), 
		  locked_inst(0) {}

	timestamp_t start;
	timestamp_t end;

	int acquire_cpu;
	int release_cpu;

	pc_t call_pc;
	pc_t acquire_pc;

	map<pc_t, uint64_t> per_pc_coherence_miss;
	uint64_t locked_inst;
};

class LockManager {
	struct LockState {
		LockState(void) 
			: ss_(), acquired_ts_(0), depth_(0) {}

		void release(const struct mtrace_lock_entry *lock) {
			depth_--;
			if (depth_ == 0) {
				ss_.end = lock->h.ts;
				ss_.release_cpu = lock->h.cpu;
			}
		}

		void acquire(const struct mtrace_lock_entry *lock) {
			if (depth_ == 0) {
				ss_.start = lock->h.ts;
				ss_.call_pc = mtrace_call_pc[lock->h.cpu];
				ss_.acquire_cpu = lock->h.cpu;
				ss_.acquire_pc = lock->pc;
			}
			depth_++;
		}

		void acquired(const struct mtrace_lock_entry *lock) {
			if (acquired_ts_ == 0) {
				acquired_ts_ = lock->h.ts;
				ss_.start = lock->h.ts;
				ss_.acquire_cpu = lock->h.cpu;
				ss_.acquire_pc = lock->pc;
			}
		}

		void access(const struct mtrace_access_entry *a) {
			if (a->traffic)
				ss_.per_pc_coherence_miss[a->pc]++;
			else if (a->lock)
				ss_.locked_inst++;
		}

		struct SerialSection ss_;
		uint64_t acquired_ts_;
		int depth_;
	};

	typedef hash_map<uint64_t, LockState *> LockStateTable;

public:
	bool release(const struct mtrace_lock_entry *lock, SerialSection &ss) {
		static int misses;
		LockState *ls;

		auto it = state_.find(lock->lock);
		if (it == state_.end()) {
			misses++;
			if (misses >= 20)
				die("LockManager: released too many unheld locks");
			return false;
		}

		ls = it->second;
		ls->release(lock);

		if (ls->depth_ == 0) {
			ss = ls->ss_;
			stack_.remove(ls);
			state_.erase(it);
			delete ls;
			return true;
		}
		return false;
	}

	void acquire(const struct mtrace_lock_entry *lock) {
		auto it = state_.find(lock->lock);

		if (it == state_.end()) {
			pair<LockStateTable::iterator, bool> r;
			LockState *ls = new LockState();
			r = state_.insert(pair<uint64_t, LockState *>(lock->lock, ls));
			if (!r.second)
				die("acquire: insert failed");
			stack_.push_front(ls);
			it = r.first;
		}
		it->second->acquire(lock);
	}

	void acquired(const struct mtrace_lock_entry *lock) {
		static int misses;

		auto it = state_.find(lock->lock);

		if (it == state_.end()) {
			misses++;
			if (misses >= 10)
				die("acquired: acquired too many missing locks");
			return;
		}
		it->second->acquired(lock);
	}

	bool access(const struct mtrace_access_entry *a, SerialSection &ss) {
		if (stack_.empty()) {
			ss.start = a->h.ts;
			ss.end = ss.start + 1;
			ss.acquire_cpu = a->h.cpu;
			ss.release_cpu = a->h.cpu;
			ss.call_pc = mtrace_call_pc[a->h.cpu];
			ss.acquire_pc = a->pc;
			if (a->traffic)
				ss.per_pc_coherence_miss[a->pc] = 1;
			else if (a->lock)
				ss.locked_inst = 1;
			return true;
		}

		stack_.front()->access(a);
		return false;
	}

private:
	LockStateTable state_;
	list<LockState *> stack_;
};

//
// A summary of every serial section and a per-acquire PC breakdown
//
class SerialSections : public EntryHandler {
	struct SerialSectionSummary {
		SerialSectionSummary(void):
			per_pc_coherence_miss(),
			ts_cycles({0}),
			acquires(0),
			mismatches(0),
			locked_inst(0) {}
		

		void add(const SerialSection *ss) {
			if (ss->acquire_cpu != ss->release_cpu) {
				mismatches++;
				return;
			}

			if (ss->end < ss->start)
				die("SerialSectionSummary::add %"PRIu64" < %"PRIu64,
				    ss->end, ss->start);

			ts_cycles[ss->acquire_cpu] += ss->end - ss->start;
			auto it = ss->per_pc_coherence_miss.begin();
			for (; it != ss->per_pc_coherence_miss.end(); ++it)
				per_pc_coherence_miss[it->first] += it->second;

			locked_inst += ss->locked_inst;
			acquires++;
		}

		timestamp_t total_cycles(void) const {
			timestamp_t sum = 0;
			int i;

			for (i = 0; i < MAX_CPUS; i++)
				sum += ts_cycles[i];
			return sum;
		}

		uint64_t coherence_misses(void) const {
			uint64_t sum = 0;

			auto it = per_pc_coherence_miss.begin();
			for (; it != per_pc_coherence_miss.end(); ++it)
				sum += it->second;
			
			return sum;
		}

		map<pc_t, uint64_t> per_pc_coherence_miss;
		timestamp_t ts_cycles[MAX_CPUS];
		uint64_t acquires;
		uint64_t mismatches;
		uint64_t locked_inst;
	};

	struct SerialSectionStat {
		SerialSectionStat(void) :
			lock_id(0),
			obj_id(0),
			name("") {}

		void add(const SerialSection *ss) {
			summary.add(ss);
			per_pc[ss->acquire_pc].add(ss);
		}

		void init(const MtraceObject *object, const struct mtrace_lock_entry *l) {
			lock_id = l->lock;
			obj_id = object->id_;
			name = l->str;
			lock_section = true;
		}

		void init(const MtraceObject *object, const struct mtrace_access_entry *a, string str) {
			lock_id = a->guest_addr;
			obj_id = object->id_;
			name = str;
			lock_section = false;
		}

		// Set by init
		uint64_t lock_id;
		uint64_t obj_id;
		string name;
		bool lock_section;

		// Updated by add
		SerialSectionSummary summary;
		map<pc_t, SerialSectionSummary> per_pc;
	};

	struct SerialSectionKey {
		uint64_t lock_id;
		uint64_t obj_id;
	};

public:
	SerialSections(void) : lock_manager_() {}

	virtual void handle(const union mtrace_entry *entry) {
		if (mtrace_enable.access.value == 0)
			return;

		switch (entry->h.type) {
		case mtrace_entry_access:
			handle_access(&entry->access);
			break;
		case mtrace_entry_lock:
			handle_lock(&entry->lock);
			break;
		default:
			die("SerialSections::handle type %u", entry->h.type);
		}
	}

	virtual void exit(void) {
		auto it = stat_.begin();

		printf("serial sections:\n");

		for (; it != stat_.end(); ++it) {
			SerialSectionStat *stat = &it->second;
			printf(" %s  %lu  %lu\n",
			       stat->name.c_str(),
			       stat->summary.ts_cycles,
			       stat->summary.acquires);
		}
	}

	virtual void exit(JsonDict *json_file) {
		JsonList *list = JsonList::create();

		auto it = stat_.begin();
		for (; it != stat_.end(); ++it) {
			SerialSectionStat *stat = &it->second;
			JsonDict *dict = JsonDict::create();
			dict->put("name", stat->name);
			dict->put("section-type", stat->lock_section ? "lock" : "instruction");
			populateSummaryDict(dict, &stat->summary);

			JsonList *pc_list = JsonList::create();
			auto mit = stat->per_pc.begin();
			for (; mit != stat->per_pc.end(); ++mit) {
				JsonDict *pc_dict = JsonDict::create();
				SerialSectionSummary *sum = &mit->second;
				pc_t pc = mit->first;

				pc_dict->put("pc", new JsonHex(pc));
				pc_dict->put("info", addr2line->function_description(pc));
				populateSummaryDict(pc_dict, sum);

				pc_list->append(pc_dict);
			}
			dict->put("per-acquire-pc", pc_list);

			list->append(dict);
		}
		json_file->put("serial-sections", list);
	}

private:
	LockManager lock_manager_;

	struct SerialEq {
		bool operator()(const SerialSectionKey s1, const SerialSectionKey s2) const
		{
			return (s1.lock_id == s2.lock_id) && (s1.obj_id == s2.obj_id);
		}
	};

	struct SerialHash {
		size_t operator()(const SerialSectionKey s) const
		{
			register uintptr_t *k = (uintptr_t *)&s;
			register uint64_t length = sizeof(s) / sizeof(uintptr_t);

			// XXX should be a static assertion
			assert(length == 2);

			return bb_hash(k, length);
		}
	};

	void populateSummaryDict(JsonDict *dict, SerialSectionSummary *sum) {
		timestamp_t tot;
		JsonList *list;
		int i;

		tot = sum->total_cycles();
		dict->put("total-cycles",  tot);
		list = JsonList::create();
		for (i = 0; i < mtrace_summary.num_cpus; i++) {
			float percent;

			percent = 0.0;
			if (tot != 0.0)
				percent = 100.0 * ((float)sum->ts_cycles[i] / (float)tot);
			list->append(percent);
		}
		dict->put("per-cpu-percent", list);
		dict->put("acquires", sum->acquires);

		JsonList *coherence_list = JsonList::create();
		auto it = sum->per_pc_coherence_miss.begin();
		for (; it != sum->per_pc_coherence_miss.end(); ++it) {
			JsonDict *coherence_dict = JsonDict::create();
			pc_t pc = it->first;
			coherence_dict->put("pc", new JsonHex(pc));
			coherence_dict->put("info", addr2line->function_description(pc));
			coherence_dict->put("count", it->second);
			coherence_list->append(coherence_dict);
		}
		dict->put("coherence-miss", sum->coherence_misses());
		dict->put("coherence-miss-list", coherence_list);

		dict->put("locked-inst", sum->locked_inst);
		dict->put("mismatches", sum->mismatches);
	}

	void handle_lock(const struct mtrace_lock_entry *l) {
		switch(l->op) {
		case mtrace_lockop_release: {
			SerialSection ss;
			if (lock_manager_.release(l, ss)) {
				MtraceObject object;
				SerialSectionKey key;

				if (!mtrace_label_map.object(l->lock, object))
					die("SerialSections::handle: missing %"PRIx64" %s", 
					    l->lock, l->str);

				key.lock_id = l->lock;
				key.obj_id = object.id_;

				auto it = stat_.find(key);
				if (it == stat_.end()) {
					stat_[key].init(&object, l);
					it = stat_.find(key);
				}
				it->second.add(&ss);
			}
			break;
		}
		case mtrace_lockop_acquire:
			lock_manager_.acquire(l);
			break;
		case mtrace_lockop_acquired:
			lock_manager_.acquired(l);
			break;
		default:
			die("SerialSections::handle: bad op");
		}
	}

	void handle_access(const struct mtrace_access_entry *a) {
		SerialSection ss;

		if (lock_manager_.access(a, ss)) {
			MtraceObject object;
			SerialSectionKey key;
			
			key.obj_id = 0;
			if (mtrace_label_map.object(a->guest_addr, object))
				key.obj_id = object.id_;
			key.lock_id = a->guest_addr;

			auto it = stat_.find(key);
			if (it == stat_.end()) {
				stat_[key].init(&object, a, object.name_);
				it = stat_.find(key);
			}
			it->second.add(&ss);
		}
	}

	hash_map<SerialSectionKey, SerialSectionStat, SerialHash, SerialEq> stat_;
};
