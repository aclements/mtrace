#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include "addr2line.hh"
extern "C"
{
#include <mtrace-magic.h>
#include "util.h"
#include "objinfo.h"
}

enum { SOURCE_LIMIT = 0 };
const char *lockname;

using namespace std;

enum LockState {
	LS_NONE = 0,
	LS_READ,
	LS_WRITE,

	NUM_LOCK_STATE
};

const char *lockStateNames[] = {
	"Unlocked",
	"Read-locked",
	"Write-locked",
};

class OffsetLockSetInfo
{
public:
	int stcount, count;
	typedef pair<uint64_t, mtrace_access_t> Access;
	map<Access, int> pcs;

	static bool
	compare_pc_count(const pair<Access, int> &a,
			 const pair<Access, int> &b) {
		return a.second > b.second;
	}

	void
	print_pcs(Addr2line *a2l, unsigned int num) {
		static const char *access_type_to_str[] = {
			NULL, "ld", "st", "iw",
		};

		if (num == 0)
			num = pcs.size();
		if (num > pcs.size())
			num = pcs.size();
		vector<pair<Access, int> > vec(pcs.begin(), pcs.end());
		partial_sort(vec.begin(), vec.begin() + num, vec.end(),
			     compare_pc_count);
		for (unsigned int i = 0; i < num; ++i) {
			char *func, *file;
			int lineno;
			if (a2l->lookup(vec[i].first.first, &func, &file, &lineno) < 0) {
				func = strdup("???");
				file = strdup("???");
				lineno = 0;
			}
			printf("    %s %6d %016llx %s %s:%d\n",
			       access_type_to_str[vec[i].first.second],
			       vec[i].second, vec[i].first.first,
			       func, file, lineno);
			free(func);
			free(file);
		}
		if (num < pcs.size())
			printf("    (+ %d more)\n", pcs.size() - num);
	}
};

class OffsetInfo
{
public:
	OffsetLockSetInfo info[NUM_LOCK_STATE];

	void access(struct mtrace_access_entry *a, LockState ls) {
		++info[ls].count;
		if (a->access_type == mtrace_access_st)
			++info[ls].stcount;
		++info[ls].pcs[make_pair(a->pc, a->access_type)];
	}
	int total(bool st) const {
		int t = 0;
		for (int i = 0; i < NUM_LOCK_STATE; ++i)
			t += st ? info[i].stcount : info[i].count;
		return t;
	}
	float freq(bool st, LockState ls) const {
		int t = total(st);
		if (t == 0)
			return 0;
		if (st)
			return (float)info[ls].stcount / t;
		return (float)info[ls].count / t;
	}
};

class LabelClass
{
public:
	int varid;
	string name;

	// Static variables
	LabelClass(int _varid) : varid(_varid) {}
	// Dynamic allocations
	LabelClass(string _name) : varid(-1), name(_name) {}

	bool operator==(LabelClass o) const {
		return o.varid == varid && o.name == name;
	}
	bool operator<(LabelClass o) const {
		if (o.varid != varid)
			return o.varid < varid;
		return o.name < name;
	}
};


typedef map<uint64_t, struct mtrace_label_entry> LabelMap;

static LabelMap labels[mtrace_label_end];
// XXX Assuming a single CPU
//static int lockSet;		// Just 0 or 1 depending on lock
static uint32_t curPID;
static map<uint32_t, LockState> lockStates;

typedef int Offset;
// XXX Might want to canonicalize the offsets by rounding them to the
// beginning of arrays and maybe base types.
typedef map<pair<LabelClass, Offset>, OffsetInfo> OffsetCountMap;
typedef vector<pair<pair<LabelClass, Offset>, OffsetInfo> > OffsetCountVector;
static OffsetCountMap offsetCounts;

static int nAccess, unresolvedAccess;

static void
process_static(struct obj_info *o)
{
	struct mtrace_label_entry l;
	struct obj_info_var var;

	l.h.type = mtrace_entry_label;
	l.h.cpu = 0xffff;
	l.h.access_count = 0;
	l.str[sizeof(l.str) - 1] = 0;
	l.label_type = mtrace_label_static;

	obj_info_vars_reset(o);
	while (obj_info_vars_next(o, &var)) {
		strncpy(l.str, var.name, sizeof(l.str) - 1);
		l.guest_addr = var.location;
		l.bytes = obj_info_type_size(o, var.idtype);
		l.host_addr = var.id; // Kludge!
		labels[l.label_type][l.guest_addr] = l;
	}
}

static void
handle_label(struct mtrace_label_entry *l)
{
	LabelMap *m = &labels[l->label_type];
	LabelMap::iterator it = m->find(l->guest_addr);
	static int misses;

	if (l->bytes) {
		// XXX Why does this have to be per label type?  If we
		// don't separate it out, there are conflicts.
		if (it != m->end())
			die("oops");
		(*m)[l->guest_addr] = *l;
	} else if (it == m->end()) {
		if (misses++ > 200)
			die("suspicious number of misses");
	} else {
		m->erase(it);
	}
}

static void
handle_access(struct mtrace_access_entry *a)
{
	nAccess++;
	// Map it to a label
	LabelMap::iterator it;
	for (int lt = mtrace_label_heap; lt < mtrace_label_end; lt++) {
		it = labels[lt].upper_bound(a->guest_addr);
		// Upper bound returns the *next* label.
		if (it == labels[lt].begin())
			continue;
		it--;
		// Check if we're in the label
		struct mtrace_label_entry *l = &it->second;
		assert(a->guest_addr >= l->guest_addr);
		if (a->guest_addr >= l->guest_addr + l->bytes)
			continue;
		// Found it
		int offset = a->guest_addr - l->guest_addr;
//		printf("A %s+0x%x %d\n", l->str, offset, lockSet);
		offsetCounts[make_pair(l->h.cpu == 0xffff ?
				       LabelClass(l->host_addr) :
				       LabelClass(l->str), offset)].
			access(a, lockStates[curPID]);
		return;
	}
	// Didn't find it
	// XXX Many of these appear to be code, I think
//	printf("A ??? %d\n", lockSet);
	unresolvedAccess++;
}

static void
handle_lock(struct mtrace_lock_entry *l)
{
	if (strcmp(l->str, lockname) != 0)
		return;

	// A single PID can hold different instances of the same lock,
	// so we track the acquire count for each PID.
	static map<uint32_t, int> pidLocks;

	LockState ls;
	LockState prev = lockStates[curPID];
	int n = pidLocks[curPID];

	if (l->release) {
		n--;
		ls = LS_NONE;
	} else {
		n++;
		ls = l->read ? LS_READ : LS_WRITE;
		if (ls < prev)
			ls = prev;
	}

	assert(n >= 0);
	pidLocks[curPID] = n;
	lockStates[curPID] = ls;
}

static void
process_entry(union mtrace_entry *e)
{
	switch (e->h.type) {
	case mtrace_entry_label:
		handle_label(&e->label);
		break;
	case mtrace_entry_access:
		handle_access(&e->access);
		break;
	case mtrace_entry_lock:
		handle_lock(&e->lock);
		break;
		fprintf(stderr, "%-3s [%-3u  pc %16lx  lock %16lx  %s]\n",
		       e->lock.release ? "r" : (e->lock.read ? "ar" : "aw"),
		       e->h.cpu,
		       e->lock.pc,
		       e->lock.lock,
		       e->lock.str);
		handle_lock(&e->lock);
		break;
	case mtrace_entry_sched:
		curPID = e->sched.pid;
		break;
	default:
		break;
	}
}

static bool
compare_offset_freq(const pair<pair<LabelClass, Offset>, OffsetInfo> &a,
		    const pair<pair<LabelClass, Offset>, OffsetInfo> &b)
{
	if (a.second.freq(true, LS_WRITE) != b.second.freq(true, LS_WRITE))
		return a.second.freq(true, LS_WRITE) > b.second.freq(true, LS_WRITE);
	return a.second.total(false) > b.second.total(false);
}

static void
print_inference(struct obj_info *vmlinux, Addr2line *a2l)
{
	static LockState lsOrder[] = {
		LS_WRITE,
		LS_READ,
		LS_NONE,
	};

	OffsetCountVector counts(offsetCounts.begin(), offsetCounts.end());

	sort(counts.begin(), counts.end(), compare_offset_freq);

	OffsetCountVector::iterator it;
	for (it = counts.begin(); it < counts.end(); ++it) {
		float stfreq = it->second.freq(true, LS_WRITE);
		float freq = 1 - it->second.freq(false, LS_NONE);
		int total = it->second.total(false);
		LabelClass *lname = &it->first.first;
		if ((stfreq < 0.95 || total < 10) &&
		    !(lname->name == "vm_area_struct" ||
		      lname->name == "mm_struct"))
			continue;

		int off = it->first.second;
		char str[128];

		int id = lname->varid;
		if (id == -1)
			id = obj_info_type_by_name(vmlinux, lname->name.c_str());
		if (id == -1)
			snprintf(str, sizeof(str), "[%s+%#x]", lname->name.c_str(), off);
		else
			obj_info_offset_name(vmlinux, id, off, str, sizeof(str));

		// XXX Hmm.  If they're all reads, then perhaps it
		// isn't protected.
		printf("%-65s %3d%% %3d%% %d\n", str,
		       (int)(stfreq*100), (int)(freq*100), total);

		for (size_t i = 0; i < sizeof(lsOrder)/sizeof(lsOrder[0]); i++) {
			LockState ls = lsOrder[i];
			if (!it->second.info[ls].pcs.size())
				continue;
			printf("  %s\n", lockStateNames[ls]);
			it->second.info[ls].print_pcs(a2l, SOURCE_LIMIT);
		}
	}
}

int
main(int argc, char **argv)
{
	gzFile log;
	int vmlinuxfd;
	struct obj_info *vmlinux;
	union mtrace_entry entry;
	int count = 0, limit = 0; //1000000;
	int r;

	if (argc != 4)
		die("usage: %s mtrace-log-file vmlinux lockname", argv[0]);
	lockname = argv[3];

	log = gzopen(argv[1], "rb");
	if (!log)
		edie("gzopen %s", argv[1]);
	if ((vmlinuxfd = open(argv[2], O_RDONLY)) < 0)
		edie("open %s", argv[2]);

	fprintf(stderr, "Loading object info...\n");
	vmlinux = obj_info_create_from_fd(vmlinuxfd);
	process_static(vmlinux);

	Addr2line a2l(argv[2]);

	fprintf(stderr, "Processing log...\n");
	while ((r = read_entry(log, &entry)) > 0) {
		if (limit && count++ > limit)
			break;
		process_entry(&entry);
	}
	if (r < 0)
		die("failed to read entry");
	gzclose(log);
	printf("# Lock frequencies for %s\n", lockname);
	printf("# %d accesses, %d unresolved\n", nAccess, unresolvedAccess);

	print_inference(vmlinux, &a2l);

	obj_info_destroy(vmlinux);
	close(vmlinuxfd);

	return 0;
}
