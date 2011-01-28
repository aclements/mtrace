#include <ext/hash_map>

using namespace::__gnu_cxx;

struct CriticalSection {
	uint64_t acquire_ts_;
	int 	 read_mode_;
	int	 start_cpu_;
	uint64_t id_;
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
			id_ = id;
			n_ = 0;
		}

		// Returns 1 if no longer held and fills in cs
		int release(CriticalSection *cs) {
			int r;

			if (n_ == 0)
				die("releasing lock with no acquires");
			r = --n_ == 0;
			if (r) {
				// The trylock code (e.g. __raw_spin_trylock in spinlock_api_smp.h.)
				// calls lock_acquire if the lock is successfully acquired and never
				// calls lock_acquired.
				//
				// The mtrace entry should probably include a 'trylock' flag, but
				// for now this hack is sufficient.
				cs->acquire_ts_ = acquire_ts_;
				if (acquired_ts_)
					cs->acquire_ts_ = acquired_ts_;

				cs->read_mode_ = read_;
				cs->start_cpu_ = start_cpu_;
				cs->id_ = id_;
			}
			return r;
		}

		void acquire(void) {
			n_++;
		}

		void acquired(struct mtrace_lock_entry *l) {
			if (acquired_ts_ == 0)
				acquired_ts_ = l->h.ts;
		}

		uint64_t lock_;
		uint64_t acquire_ts_;
		uint64_t acquired_ts_;
		uint64_t id_;
		int start_cpu_;
		int read_;
		int n_;
	};

	typedef hash_map<uint64_t, struct LockState> LockStateTable;

public:
	bool release(struct mtrace_lock_entry *lock, struct CriticalSection *cs)
	{
		LockStateTable::iterator it = state_.find(lock->lock);

		if (it == state_.end()) {
			//printf("LockSet: releasing unheld lock %lx\n", lock->lock);
			return false;
		}

		if (it->second.release(cs)) {
			state_.erase(it);
			return true;
		}
		return false;
	}

	void acquire(struct mtrace_lock_entry *lock, uint64_t id) {
		LockStateTable::iterator it = state_.find(lock->lock);		

		if (it == state_.end()) {
			pair<LockStateTable::iterator, bool> r;
			LockState ls(lock, id);
			r = state_.insert(pair<uint64_t, struct LockState>(lock->lock, ls));
			if (!r.second)
				die("on_lock: insert failed");
			it = r.first;
		}
		it->second.acquire();
	}

	void acquired(struct mtrace_lock_entry *lock) {
		LockStateTable::iterator it = state_.find(lock->lock);		

		if (it == state_.end())
			die("acquired: missing lock");
		it->second.acquired(lock);
	}

private:
	hash_map<uint64_t, struct LockState> state_;
};
