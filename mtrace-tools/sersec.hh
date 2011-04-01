#include <ext/hash_map>

using namespace::std;
using namespace::__gnu_cxx;

struct SerialSection {
	timestamp_t start;
	timestamp_t end;
	pc_t call_pc;
};

class LockManager {
	struct LockState {
		LockState(const struct mtrace_lock_entry *lock, pc_t call_pc) {
			ss_.call_pc = call_pc;
			ss_.start = lock->h.ts;
			acquired_ts_ = 0;
			depth_ = 0;
		}

		void release(void) {
			depth_--;
		}

		void acquire(void) {
			depth_++;
		}

		void acquired(const struct mtrace_lock_entry *lock) {
			if (acquired_ts_ == 0) {
				acquired_ts_ = lock->h.ts;
				ss_.start = lock->h.ts;
			}
		}

		struct SerialSection ss_;
		uint64_t acquired_ts_;
		int depth_;
	};

	typedef hash_map<uint64_t, LockState *> LockStateTable;

public:
	bool release(const struct mtrace_lock_entry *lock, SerialSection *ss) {
		static int misses;

		auto it = state_.find(lock->lock);
		if (it == state_.end()) {
			misses++;
			if (misses >= 20)
				die("LockManager: released too many unheld locks");
		}

		it->second->release();

		if (it->second->depth_ == 0) {
			memcpy(ss, &it->second->ss_, sizeof(*ss));
			delete it->second;
			state_.erase(it);
			return true;
		}
		return false;
	}

	void acquire(const struct mtrace_lock_entry *lock) {
		auto it = state_.find(lock->lock);		

		if (it == state_.end()) {
			pair<LockStateTable::iterator, bool> r;
			LockState *ls = new LockState(lock, mtrace_call_pc[lock->h.cpu]);
			r = state_.insert(pair<uint64_t, LockState *>(lock->lock, ls));
			if (!r.second)
				die("acquire: insert failed");
			stack_.push_front(ls);
			it = r.first;
		}
		it->second->acquire();
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

private:
	LockStateTable state_;
	list<LockState *> stack_;
};

class SerialSections : public EntryHandler {
public:
	SerialSections(void) : lock_manager_() {}

	virtual void handle(const union mtrace_entry *entry) {
		const struct mtrace_lock_entry *l;
		
		if (mtrace_enable.access.value == 0)
			return;

		l = &entry->lock;
		switch(l->op) {
		case mtrace_lockop_release: {
			SerialSection ss;
			if (lock_manager_.release(l, &ss)) {
				/* XXX */
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

	virtual void exit(void) {
		printf("SerialSections::exit: XXX\n");
	}

private:
	LockManager lock_manager_;
};
