#include <ext/hash_map>
#include <assert.h>

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
			ss->end = lock->h.ts;
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
	struct SerialSectionStat {
		SerialSectionStat(void) : 
			lock_id(0), obj_id(0), name(""), ts_cycles(0), acquires(0) {}

		void add(const SerialSection *ss) {
			ts_cycles += ss->end - ss->start;
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
	};

	struct SerialSectionKey {
		uint64_t lock_id;
		uint64_t obj_id;
	};

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
				MtraceObject object;
				SerialSectionKey key;

				if (!mtrace_label_map.lower_bound(l->lock, &object))
					die("SerialSections::handle: missing %lx", l->lock);
				
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

	virtual void exit(void) {
		auto it = stat_.begin();
		
		for (; it != stat_.end(); ++it) {
			printf("%s\n", it->second.name.c_str());
		}
		printf("SerialSections::exit: XXX\n");
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
			/* hash function from: http://burtleburtle.net/bob/hash/evahash.html */
			#define mix64(a,b,c) \
			{	     \
				a -= b; a -= c; a ^= (c>>43);	\
				b -= c; b -= a; b ^= (a<<9);	\
				c -= a; c -= b; c ^= (b>>8);	\
				a -= b; a -= c; a ^= (c>>38);	\
				b -= c; b -= a; b ^= (a<<23);	\
				c -= a; c -= b; c ^= (b>>5);	\
				a -= b; a -= c; a ^= (c>>35);	\
				b -= c; b -= a; b ^= (a<<49);	\
				c -= a; c -= b; c ^= (b>>11);	\
				a -= b; a -= c; a ^= (c>>12);	\
				b -= c; b -= a; b ^= (a<<18);	\
				c -= a; c -= b; c ^= (b>>22);	\
			}

			register uintptr_t *k = (uintptr_t *)&s;
			register uint64_t length = sizeof(s) / sizeof(uintptr_t);
			register uint64_t a, b, c, len;
			
			assert(length == 2);

			/* Set up the internal state */
			len = length;
			a = b = 0xdeadbeef;		/* the previous hash value */
			c = 0x9e3779b97f4a7c13LL;	/* the golden ratio; an arbitrary value */
			
			while (len >= 3) {
				a += k[0];
				b += k[1];
				c += k[2];
				mix64(a, b, c);
				k += 3;
				len -= 3;
			}
			
			c += length;
			switch (len) {		/* all the case statements fall through */
			case 2:
				b += k[1];
			case 1:
				a += k[0];
			default:
				;
			}
			
			mix64(a, b, c);
			return c;
		}
	};
	
	hash_map<SerialSectionKey, SerialSectionStat, SerialHash, SerialEq> stat_;
};
