#include <ext/hash_map>

using namespace::__gnu_cxx;

struct CriticalSection {
	uint64_t acquire_ts_;
	uint64_t spin_locked_accesses_;
	uint64_t spin_traffic_accesses_;
	uint64_t spin_cycles_;
	uint64_t pc_;
	int 	 read_mode_;
	int	 start_cpu_;
	uint64_t id_;
	uint64_t locked_accesses_;
	uint64_t traffic_accesses_;
	uint64_t call_trace_tag_;
	char	 str_[32];
};

class LockSet {
private:
	struct LockState {
		LockState(struct mtrace_lock_entry *l, uint64_t id, uint64_t call_trace_tag) {
			memset(&cs_, 0, sizeof(cs_));

			cs_.read_mode_ = l->read;
			cs_.acquire_ts_ = l->h.ts;
			cs_.start_cpu_ = l->h.cpu;
			cs_.pc_ = l->pc;
			cs_.id_ = id;
			cs_.call_trace_tag_ = call_trace_tag;
			strcpy(cs_.str_, l->str);

			acquired_ts_ = 0;
			n_ = 0;
		}

		// Returns 1 if no longer held and fills in cs
		int release(CriticalSection *cs) {
			int r;

			if (n_ == 0)
				die("releasing lock with no acquires");
			r = --n_ == 0;
			if (r)
				get_critical_section(cs);
			return r;
		}

		void acquire(void) {
			n_++;
		}

		void acquired(struct mtrace_lock_entry *l) {
			if (acquired_ts_ == 0) {
				acquired_ts_ = l->h.ts;

				cs_.spin_cycles_ = acquired_ts_ - cs_.acquire_ts_;
				cs_.spin_locked_accesses_ = cs_.locked_accesses_;
				cs_.spin_traffic_accesses_ = cs_.traffic_accesses_;
				cs_.locked_accesses_ = 0;
				cs_.traffic_accesses_ = 0;
				cs_.acquire_ts_ = acquired_ts_;
			}
		}

		void get_critical_section(CriticalSection *cs) {
			memcpy(cs, &cs_, sizeof(*cs));
		}

		void on_access(struct mtrace_access_entry *a) {
			if (a->traffic)
				cs_.traffic_accesses_++;
			else if (a->lock)
				cs_.locked_accesses_++;
			else
				die("on_access: bad access");
		}

		struct CriticalSection cs_;

		uint64_t acquired_ts_;
		int n_;
	};

	typedef hash_map<uint64_t, LockState *> LockStateTable;

public:
	bool release(struct mtrace_lock_entry *lock, struct CriticalSection *cs)
	{
		static int misses;

		LockStateTable::iterator it = state_.find(lock->lock);

		if (it == state_.end()) {
			misses++;
			if (misses >= 20)
				die("LockSet: released too many unheld locks\n");
			return false;
		}

		if (it->second->release(cs)) {
			LockState *ls = it->second;
			state_.erase(it);
			stack_.remove(ls);
			delete ls;
			return true;
		}
		return false;
	}

	void acquire(struct mtrace_lock_entry *lock, uint64_t id, uint64_t call_trace_tag) {
		LockStateTable::iterator it = state_.find(lock->lock);		

		if (it == state_.end()) {
			pair<LockStateTable::iterator, bool> r;
			LockState *ls = new LockState(lock, id, call_trace_tag);
			r = state_.insert(pair<uint64_t, LockState *>(lock->lock, ls));
			if (!r.second)
				die("on_lock: insert failed");
			stack_.push_front(ls);
			it = r.first;
		}
		it->second->acquire();
	}

	void acquired(struct mtrace_lock_entry *lock) {
		static int misses;

		LockStateTable::iterator it = state_.find(lock->lock);		

		if (it == state_.end()) {
			misses++;
			if (misses >= 10)
				die("LockSet: acquired too many missing locks");

			return;
		}
		it->second->acquired(lock);
	}

	void on_access(struct mtrace_access_entry *a) {
		if (stack_.empty())
			die("top: stack is empty");
		stack_.front()->on_access(a);
	}

	bool empty(void) {
		return stack_.empty();
	}

	void top(CriticalSection *cs) {
		if (stack_.empty())
			die("top: stack is empty");
		stack_.front()->get_critical_section(cs);
	}

private:
	LockStateTable state_;
	list<LockState *> stack_;
};
