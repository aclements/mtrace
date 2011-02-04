#include <ext/hash_map>

using namespace::__gnu_cxx;

struct CriticalSection {
	uint64_t acquire_ts_;
	uint64_t spin_time_;
	uint64_t pc_;
	int 	 read_mode_;
	int	 start_cpu_;
	uint64_t id_;
	char	 str_[32];
};

class LockSet {
private:
	struct LockState {
		LockState(struct mtrace_lock_entry *l, uint64_t id) {
			lock_ = l->lock;
			read_ = l->read;
			acquire_ts_ = l->h.ts;
			acquired_ts_ = 0;
			start_cpu_ = l->h.cpu;
			pc_ = l->pc;
			id_ = id;
			n_ = 0;
			strcpy(str_, l->str);
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
			if (acquired_ts_ == 0)
				acquired_ts_ = l->h.ts;
		}

		void get_critical_section(CriticalSection *cs) {
			cs->spin_time_ = 0;
			// The trylock code (e.g. __raw_spin_trylock in spinlock_api_smp.h.)
			// calls lock_acquire if the lock is successfully acquired and never
			// calls lock_acquired.
			//
			// The mtrace entry should probably include a 'trylock' flag, but
			// for now this hack is sufficient.
			cs->acquire_ts_ = acquire_ts_;
			if (acquired_ts_) {
				cs->acquire_ts_ = acquired_ts_;
				cs->spin_time_ = acquired_ts_ - acquire_ts_;
			}

			cs->read_mode_ = read_;
			cs->start_cpu_ = start_cpu_;
			cs->id_ = id_;
			cs->pc_ = pc_;
			strcpy(cs->str_, str_);
		}

		uint64_t lock_;
		uint64_t acquire_ts_;
		uint64_t pc_;
		uint64_t acquired_ts_;
		uint64_t id_;
		int start_cpu_;
		int read_;
		int n_;
		char str_[32];
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

	void acquire(struct mtrace_lock_entry *lock, uint64_t id) {
		LockStateTable::iterator it = state_.find(lock->lock);		

		if (it == state_.end()) {
			pair<LockStateTable::iterator, bool> r;
			LockState *ls = new LockState(lock, id);
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
