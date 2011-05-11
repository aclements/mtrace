#include <ext/hash_map>
#include <assert.h>
#include <cinttypes>

#include "json.hh"
#include "hash.h"

using namespace::std;
using namespace::__gnu_cxx;

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
	timestamp_t start;
	timestamp_t end;

	int acquire_cpu;
	int release_cpu;

	pc_t call_pc;

	uint64_t coherence_miss;
	uint64_t locked_inst;
};

class LockManager {
	struct LockState {
		LockState(void) : acquired_ts_(0), depth_(0) {
			memset(&ss_, 0, sizeof(ss_));
		}

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
			}
			depth_++;
		}

		void acquired(const struct mtrace_lock_entry *lock) {
			if (acquired_ts_ == 0) {
				acquired_ts_ = lock->h.ts;
				ss_.start = lock->h.ts;
				ss_.acquire_cpu = lock->h.cpu;
			}
		}

		void access(const struct mtrace_access_entry *a) {
			if (a->traffic)
				ss_.coherence_miss++;
			else if (a->lock)
				ss_.locked_inst++;
		}

		struct SerialSection ss_;
		uint64_t acquired_ts_;
		int depth_;
	};

	typedef hash_map<uint64_t, LockState *> LockStateTable;

public:
	bool release(const struct mtrace_lock_entry *lock, SerialSection *ss) {
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
			memcpy(ss, &ls->ss_, sizeof(*ss));
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

	void access(const struct mtrace_access_entry *a) {
		if (stack_.empty())
			return;

		stack_.front()->access(a);
	}

private:
	LockStateTable state_;
	list<LockState *> stack_;
};

class SerialSections : public EntryHandler {
	struct SerialSectionStat {
		SerialSectionStat(void) :
			lock_id(0),
			obj_id(0),
			name(""),
			ts_cycles(0),
			acquires(0),
			mismatches(0),
			coherence_miss(0),
			locked_inst(0) {}

		void add(const SerialSection *ss) {
			if (ss->acquire_cpu != ss->release_cpu) {
				mismatches++;
				return;
			}

			if (ss->end < ss->start)
			    die("SerialSections::add %"PRIu64" < %"PRIu64,
				ss->end, ss->start);

			ts_cycles += ss->end - ss->start;
			coherence_miss += ss->coherence_miss;
			locked_inst += ss->locked_inst;
			acquires++;
		}

		void init(const MtraceObject *object, const struct mtrace_lock_entry *l) {
			lock_id = l->lock;
			obj_id = object->id_;
			name = l->str;
		}

		// Set by init
		uint64_t lock_id;
		uint64_t obj_id;
		string name;

		// Updated by add
		timestamp_t ts_cycles;
		uint64_t acquires;
		uint64_t mismatches;
		uint64_t coherence_miss;
		uint64_t locked_inst;
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
			       stat->ts_cycles,
			       stat->acquires);
		}
	}

	virtual void exit(JsonDict *json_file) {
		JsonList *list = JsonList::create();

		auto it = stat_.begin();
		for (; it != stat_.end(); ++it) {
			SerialSectionStat *stat = &it->second;
			JsonDict *dict = JsonDict::create();
			dict->put("name", stat->name);
			dict->put("cycles",  stat->ts_cycles);
			dict->put("acquires", stat->acquires);
			dict->put("coherence-miss", stat->coherence_miss);
			dict->put("locked-inst", stat->locked_inst);
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

	void handle_lock(const struct mtrace_lock_entry *l) {
		switch(l->op) {
		case mtrace_lockop_release: {
			SerialSection ss;
			if (lock_manager_.release(l, &ss)) {
				MtraceObject object;
				SerialSectionKey key;

				if (!mtrace_label_map.lower_bound(l->lock, &object))
					die("SerialSections::handle: missing %"PRIu64, l->lock);

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
		lock_manager_.access(a);
	}

	hash_map<SerialSectionKey, SerialSectionStat, SerialHash, SerialEq> stat_;
};
