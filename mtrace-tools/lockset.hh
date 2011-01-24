#include <ext/hash_map>

using namespace::__gnu_cxx;

class LockSet {
private:
	struct LockState {
		LockState(struct mtrace_lock_entry *l) {
			lock_ = l;
			n_ = 0;
		}

		// Returns 1 if no longer held
		int release(void) {
			int r;

			if (n_ == 0)
				die("releasing lock with no acquires");
			r = --n_ == 0;
			if (r)
				free(lock_);
			return r;
		}

		void acquire(void) {
			n_++;
		}

		struct mtrace_lock_entry *lock_;
		int n_;
	};

	typedef hash_map<uint64_t, struct LockState> LockStateTable;

public:
	~LockSet(void) {
		LockStateTable::iterator it = state_.begin();
		for (; it != state_.end(); ++it)
			free(it->second.lock_);
	}

	void on_lock(struct mtrace_lock_entry *lock) {
		LockStateTable::iterator it = state_.find(lock->lock);

		if (lock->release) {
			if (it == state_.end()) {
				//printf("LockSet: releasing unheld lock %lx\n", lock->lock);
				free(lock);
				return;
			}
			if (it->second.release())
				state_.erase(it);
		} else {
			if (it == state_.end()) {
				pair<LockStateTable::iterator, bool> r;
				LockState ls(lock);
				r = state_.insert(pair<uint64_t, struct LockState>(lock->lock, ls));
				if (!r.second)
					die("on_lock: insert failed");
				it = r.first;
			}

			it->second.acquire();
		}
	}

private:
	hash_map<uint64_t, struct LockState> state_;
};
