#include <stdint.h>
#include <stdio.h>
#include "util.h"

static void print_entry(union mtrace_entry *entry)
{
	static const char *access_type_to_str[] = {
		[mtrace_access_ld] = "ld",
		[mtrace_access_st] = "st",
		[mtrace_access_iw] = "iw",
	};
	
	switch(entry->h.type) {
	case mtrace_entry_label:
		printf("%-3s [%-3u  %16s  %016lx  %016lx  %016lx  %016lx  %016lx]\n",
		       "T",
		       entry->label.label_type,
		       entry->label.str,
                       entry->label.pc,
		       entry->label.host_addr,
		       entry->label.guest_addr,
		       entry->label.bytes,
		       entry->h.access_count);
		break;
	case mtrace_entry_access:
		printf("%-3s [%-3u %16lu  %016lx  %016lx  %016lx]\n", 
		       access_type_to_str[entry->access.access_type],
		       entry->h.cpu,
		       entry->h.access_count,
		       entry->access.pc,
		       entry->access.host_addr,
		       entry->access.guest_addr);
		break;
	case mtrace_entry_host:
		printf("%-3s [%u]\n", 
		       "E", entry->host.access.value);
		break;
	case mtrace_entry_fcall:
		printf("%-3s [%-3u  %16lu  %16lu  %016lx"
		       "  %016lx  %4u  %1u]\n",
		       "C",
		       entry->h.cpu,
		       entry->h.access_count,
		       entry->fcall.tid,
		       entry->fcall.pc,
		       entry->fcall.tag,
		       entry->fcall.depth,
		       entry->fcall.state);
		break;
	case mtrace_entry_segment:
		printf("%-3s [%-3u  %3u  %16lx %16lx]\n",
		       "S",
		       entry->h.cpu,
		       entry->h.type,
		       entry->seg.baseaddr,
		       entry->seg.endaddr);
		break;
	case mtrace_entry_call:
		printf("%-3s [%-3u  %4s  %16lu  %16lx %16lx]\n",
		       "L",
		       entry->h.cpu,
		       entry->call.ret ? "ret" : "call",
		       entry->h.access_count,
		       entry->call.target_pc,
		       entry->call.return_pc);
		break;
	case mtrace_entry_lock:
		printf("%-3s [%-3u  pc %16lx  lock %16lx  %s]\n",
		       entry->lock.op == mtrace_lockop_release ? "r" 
		       		      : (entry->lock.read ? "ar" : "aw"),
		       entry->h.cpu,
		       entry->lock.pc,
		       entry->lock.lock,
		       entry->lock.str);
		break;
        case mtrace_entry_sched:
		printf("%-3s [%-3u  pid %5u]\n",
		       "sch",
		       entry->h.cpu,
		       entry->sched.tid);
		break;
	default:
		fprintf(stderr, "print_entry: bad type %u\n", entry->h.type);
	}
}

int main(int argc, char **argv)
{
	union mtrace_entry entry;
	gzFile fp;
	int r;

	if (argc != 2)
		die("usage: %s mtrace-log-file", argv[0]);
	fp = gzopen(argv[1], "rb");
	if (!fp)
		edie("gzopen %s", argv[0]);
	while ((r = read_entry(fp, &entry)) > 0)
		print_entry(&entry);
	if (r < 0)
		die("failed to read entry");
	gzclose(fp);
	return 0;
}
