// -*- mode: c; indent-tabs-mode: t; c-file-style: "bsd" -*-
#define __STDC_FORMAT_MACROS
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "util.h"

static void print_entry(union mtrace_entry *entry)
{
	static const char *access_type_to_str[] = {
		[mtrace_access_ld] = "ld",
		[mtrace_access_st] = "st",
		[mtrace_access_iw] = "iw",
	};
	static const char *call_state_to_str[] = {
		[mtrace_start]  = "start",
		[mtrace_done]   = "done",
		[mtrace_resume] = "resume",
		[mtrace_pause]  = "pause",
	};
	static const char *host_to_str[] = {
		[mtrace_access_all_cpu]    = "access_all_cpu",

		[mtrace_call_clear_cpu]    = "call_clear_cpu",
		[mtrace_call_set_cpu]      = "call_set_cpu",

		[mtrace_disable_count_cpu] = "disable_count_cpu",
		[mtrace_enable_count_cpu]  = "enable_count_cpu",
	};
	static const char *record_mode_to_str[] = {
		[mtrace_record_disable]    = "disable",
		[mtrace_record_movement]   = "movement",
		[mtrace_record_ascope]     = "ascope",
	};
	static const char *task_to_str[] = {
		[mtrace_task_init]   = "init",
		[mtrace_task_update] = "update",
		[mtrace_task_exit]   = "exit",
	};

	switch(entry->h.type) {
	case mtrace_entry_label:
		printf("%-3s [%-3u  %16s  %016"PRIx64"  %016"PRIx64"  %016"PRIx64"  %016"PRIx64"  %016"PRIx64"]\n",
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
		printf("%-3s [%-3u %16"PRIu64" pc %016"PRIx64"  host %016"PRIx64"  guest %016"PRIx64"  %db",
		       access_type_to_str[entry->access.access_type],
		       entry->h.cpu,
		       entry->h.access_count,
		       entry->access.pc,
		       entry->access.host_addr,
		       entry->access.guest_addr,
		       entry->access.bytes);
		if (entry->access.traffic)
			printf("  traffic");
		if (entry->access.lock)
			printf("  lock");
		printf("]\n");
		break;
	case mtrace_entry_host:
		printf("%-3s [%-3u  %s",
		       "E",
		       entry->h.cpu,
		       host_to_str[entry->host.host_type]);
		switch (entry->host.host_type) {
		case mtrace_access_all_cpu:
			printf("  mode %s  %s",
			       record_mode_to_str[entry->host.access.mode],
			       entry->host.access.str);
			break;
		case mtrace_call_clear_cpu:
		case mtrace_call_set_cpu:
			printf("  cpu");
			if (entry->host.call.cpu == ~0UL)
				printf(" cur");
			else
				printf(" %"PRIu64, entry->host.call.cpu);
			break;
		default:
			break;
		}
		printf("]\n");
		break;
	case mtrace_entry_fcall:
		printf("%-3s [%-3u  %16"PRIu64"  tid %"PRIu64"  pc %016"PRIx64
		       "  tag 0x%"PRIx64"  depth %"PRIu16"  %s]\n",
		       "C",
		       entry->h.cpu,
		       entry->h.access_count,
		       entry->fcall.tid,
		       entry->fcall.pc,
		       entry->fcall.tag,
		       entry->fcall.depth,
		       call_state_to_str[entry->fcall.state]);
		break;
	case mtrace_entry_segment:
		printf("%-3s [%-3u  %3u  %16"PRIx64" %16"PRIx64"]\n",
		       "S",
		       entry->h.cpu,
		       entry->h.type,
		       entry->seg.baseaddr,
		       entry->seg.endaddr);
		break;
	case mtrace_entry_call:
		printf("%-3s [%-3u  %4s  %16"PRIu64"  %16"PRIx64" %16"PRIx64"]\n",
		       "L",
		       entry->h.cpu,
		       entry->call.ret ? "ret" : "call",
		       entry->h.access_count,
		       entry->call.target_pc,
		       entry->call.return_pc);
		break;
	case mtrace_entry_lock:
		printf("%-3s [%-3u  pc %16"PRIx64"  lock %16"PRIx64"  %s]\n",
		       entry->lock.op == mtrace_lockop_release ? "r" 
		       		      : (entry->lock.read ? "ar" : "aw"),
		       entry->h.cpu,
		       entry->lock.pc,
		       entry->lock.lock,
		       entry->lock.str);
		break;
	case mtrace_entry_task:
		printf("%-3s [%-3u %-6s  tid %16"PRIu64"  tgid  %16"PRIu64"  %s]\n",
		       "tsk",
		       entry->h.cpu,
		       task_to_str[entry->task.task_type],
		       entry->task.tid,
		       entry->task.tgid,
		       entry->task.str);
		break;
        case mtrace_entry_sched:
		printf("%-3s [%-3u  pid %5"PRIu64"]\n",
		       "sch",
		       entry->h.cpu,
		       entry->sched.tid);
		break;
	case mtrace_entry_machine:
		printf("%-3s [cpus %"PRIu16"  ram %"PRIu64"  quantum %"PRIu64
		       "  sample %"PRIu64"  locked %c  calls %c]\n",
		       "mac",
		       entry->machine.num_cpus,
		       entry->machine.num_ram,
		       entry->machine.quantum,
		       entry->machine.sample,
		       entry->machine.locked ? 't' : 'f',
		       entry->machine.calls ? 't' : 'f');
		break;
	case mtrace_entry_appdata:
		printf("%-3s [%-3u  type %"PRIu16"  u64 %"PRIu64"]\n",
		       "app",
		       entry->h.cpu,
		       entry->appdata.appdata_type,
		       entry->appdata.u64);
		break;
	case mtrace_entry_ascope:
		printf("%-3s [%-3u  %-5s %s]\n",
		       "Asc",
		       entry->h.cpu,
		       entry->ascope.exit ? "exit" : "enter",
		       entry->ascope.name);
		break;
	case mtrace_entry_avar:
		printf("%-3s [%-3u  %s]\n",
		       entry->avar.write ? "Aw" : "Ar",
		       entry->h.cpu,
		       entry->avar.name);
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
