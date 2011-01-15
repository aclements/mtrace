#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

extern "C"
{
#include <mtrace-magic.h>
#include "util.h"
#include "objinfo.h"
}

using namespace std;

class OffsetInfo
{
public:
	int counts[2];

	int total() const {
		return counts[0] + counts[1];
	}
	float freq(int ls) const {
		return (float)counts[ls] / total();
	}
};

typedef map<uint64_t, struct mtrace_label_entry> LabelMap;

static LabelMap labels[mtrace_label_end];
// XXX Assuming a single CPU
static int lockSet;		// Just 0 or 1 depending on mmap_sem

typedef string LabelName;
typedef int Offset;
typedef map<pair<LabelName, Offset>, OffsetInfo> OffsetCountMap;
typedef vector<pair<pair<LabelName, Offset>, OffsetInfo> > OffsetCountVector;
static OffsetCountMap offsetCounts;

static int unknownAccess;

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
		offsetCounts[make_pair(l->str, offset)].counts[lockSet]++;
		return;
	}
	// Didn't find it
	// XXX Static symbols
//	printf("A ??? %d\n", lockSet);
	unknownAccess++;
}

static void
handle_lock(struct mtrace_lock_entry *l)
{
	static int held;

	if (strcmp(l->str, "&mm->mmap_sem") != 0)
		return;

	if (l->release)
		held--;
	else
		held++;

	assert(held >= 0);
	lockSet = (held > 0);
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
		printf("%-3s [%-3u  pc %16lx  lock %16lx  %s]\n",
		       e->lock.release ? "r" : (e->lock.read ? "ar" : "aw"),
		       e->h.cpu,
		       e->lock.pc,
		       e->lock.lock,
		       e->lock.str);
		break;
	default:
		break;
	}
}

static bool
compare_offset_freq(const pair<pair<LabelName, Offset>, OffsetInfo> &a,
		    const pair<pair<LabelName, Offset>, OffsetInfo> &b)
{
	if (a.second.freq(1) != b.second.freq(1))
		return a.second.freq(1) > b.second.freq(1);
	return a.second.total() > b.second.total();
}

static void
print_inference(struct obj_info *vmlinux)
{
	OffsetCountVector counts(offsetCounts.begin(), offsetCounts.end());

	sort(counts.begin(), counts.end(), compare_offset_freq);

	OffsetCountVector::iterator it;
	for (it = counts.begin(); it < counts.end(); ++it) {
		float freq = it->second.freq(1);
		int total = it->second.total();
		const char *tname = it->first.first.c_str();
		if ((freq < 0.8 || total < 10) && strcmp(tname, "vm_area_struct") != 0)
			continue;

		int off = it->first.second;
		char str[128];

		if (obj_info_lookup_struct_offset(vmlinux, tname, off,
						  str, sizeof(str)) < 0)
			snprintf(str, sizeof(str), "%s+%#x", tname, off);

		printf("%-50s %3d%% %d\n", str, (int)(freq*100),
		       it->second.total());
	}
}

int
main(int argc, char **argv)
{
	gzFile log;
	int vmlinuxfd;
	struct obj_info *vmlinux;
	union mtrace_entry entry;
	int r;

	if (argc != 3)
		die("usage: %s mtrace-log-file vmlinux", argv[0]);

	log = gzopen(argv[1], "rb");
	if (!log)
		edie("gzopen %s", argv[1]);
	if ((vmlinuxfd = open(argv[2], O_RDONLY)) < 0)
		edie("open %s", argv[2]);

	printf("Processing log...\n");
	while ((r = read_entry(log, &entry)) > 0)
		process_entry(&entry);
	if (r < 0)
		die("failed to read entry");
	gzclose(log);
	printf("%d unknown accesses\n", unknownAccess);

	printf("Resolving structs...\n");
	vmlinux = obj_info_create_from_fd(vmlinuxfd);

	print_inference(vmlinux);

	obj_info_destroy(vmlinux);
	close(vmlinuxfd);

	return 0;
}
