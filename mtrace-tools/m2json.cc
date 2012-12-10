// -*- mode: c; indent-tabs-mode: t; c-file-style: "bsd" -*-
#define __STDC_FORMAT_MACROS
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <iostream>
#include "util.h"
#include "json.hh"

static JsonList* thelist;

static void handle_entry(union mtrace_entry *entry)
{
        JsonDict* je = JsonDict::create();

        je->put("cpu", entry->h.cpu);
        je->put("access_count", entry->h.access_count);

	switch(entry->h.type) {
	case mtrace_entry_label:
                je->put("type", "label");
                je->put("label_type", entry->label.label_type);
                je->put("label", entry->label.str);
                je->put("pc", new JsonHex(entry->label.pc));
                je->put("host_addr", new JsonHex(entry->label.host_addr));
                je->put("guest_addr", new JsonHex(entry->label.guest_addr));
                je->put("bytes", entry->label.bytes);
		break;
	case mtrace_entry_access:
                je->put("type", "access");
                je->put("acctype",
                        entry->access.access_type == mtrace_access_ld ? "ld" :
                        entry->access.access_type == mtrace_access_st ? "st" :
                        entry->access.access_type == mtrace_access_iw ? "iw" :
                        "unknown");
                je->put("pc", new JsonHex(entry->access.pc));
                je->put("host_addr", new JsonHex(entry->access.host_addr));
                je->put("guest_addr", new JsonHex(entry->access.guest_addr));
                je->put("bytes", entry->access.bytes);
                je->put("traffic", entry->access.traffic);
                je->put("lock", entry->access.lock);
		break;
	case mtrace_entry_host:
                je->put("type", "host");
                je->put("host_type",
                        entry->host.host_type == mtrace_access_all_cpu ? "access_all_cpu" :
                        entry->host.host_type == mtrace_call_clear_cpu ? "clear_cpu" :
                        entry->host.host_type == mtrace_call_set_cpu ? "set_cpu" :
                        entry->host.host_type == mtrace_disable_count_cpu ? "disable_count_cpu" :
                        entry->host.host_type == mtrace_enable_count_cpu ? "enable_count_cpu" :
                        "unknown");
		switch (entry->host.host_type) {
		case mtrace_access_all_cpu:
                        je->put("mode",
                                entry->host.access.mode == mtrace_record_disable ? "disable" :
                                entry->host.access.mode == mtrace_record_movement ? "movement" :
                                entry->host.access.mode == mtrace_record_ascope ? "ascope" :
                                "unknown");
                        je->put("access_str", entry->host.access.str);
			break;
		case mtrace_call_clear_cpu:
		case mtrace_call_set_cpu:
			if (entry->host.call.cpu == ~0UL)
				je->put("call_cpu", "cur");
			else
				je->put("call_cpu", entry->host.call.cpu);
			break;
		default:
			break;
		}
		break;
	case mtrace_entry_fcall:
                je->put("type", "fcall");
                je->put("tid", entry->fcall.tid);
		je->put("pc", new JsonHex(entry->fcall.pc));
                je->put("tag", entry->fcall.tag);
		je->put("depth", entry->fcall.depth);
                je->put("state",
                        entry->fcall.state == mtrace_start ? "start" :
                        entry->fcall.state == mtrace_done ? "done" :
                        entry->fcall.state == mtrace_resume ? "resume" :
                        entry->fcall.state == mtrace_pause ? "pause" :
                        "unknown");
		break;
	case mtrace_entry_segment:
                je->put("type", "segment");
                je->put("baseaddr", new JsonHex(entry->seg.baseaddr));
		je->put("endaddr", new JsonHex(entry->seg.endaddr));
		break;
	case mtrace_entry_call:
                je->put("type", "call");
                je->put("ret", entry->call.ret);
                je->put("target_pc", new JsonHex(entry->call.target_pc));
		je->put("return_pc", new JsonHex(entry->call.return_pc));
		break;
	case mtrace_entry_lock:
                je->put("type", "lock");
                je->put("op",
		        entry->lock.op == mtrace_lockop_release ? "r" :
                        (entry->lock.read ? "ar" : "aw"));
                je->put("pc", new JsonHex(entry->lock.pc));
		je->put("lock", new JsonHex(entry->lock.lock));
		je->put("str", entry->lock.str);
		break;
	case mtrace_entry_task:
                je->put("type", "task");
                je->put("tasktype",
                        entry->task.task_type == mtrace_task_init ? "init" :
                        entry->task.task_type == mtrace_task_update ? "update" :
                        entry->task.task_type == mtrace_task_exit ? "exit" :
                        "unknown");
                je->put("tid", entry->task.tid);
                je->put("tgid", entry->task.tgid);
                je->put("str", entry->task.str);
		break;
        case mtrace_entry_sched:
                je->put("type", "sched");
                je->put("tid", entry->sched.tid);
		break;
	case mtrace_entry_machine:
                je->put("type", "machine");
                je->put("ncpu", entry->machine.num_cpus);
                je->put("nram", entry->machine.num_ram);
		je->put("quantum", entry->machine.quantum);
		je->put("sample", entry->machine.sample);
		je->put("locked", entry->machine.locked);
                je->put("calls", entry->machine.calls);
		break;
	case mtrace_entry_appdata:
                je->put("type", "app");
                je->put("apptype", entry->appdata.appdata_type);
		je->put("appval", entry->appdata.u64);
		break;
	case mtrace_entry_ascope:
                je->put("type", "ascope");
                je->put("exit", entry->ascope.exit);
                je->put("name", entry->ascope.name);
		break;
	case mtrace_entry_avar:
                je->put("type", "avar");
                je->put("write", entry->avar.write);
                je->put("name", entry->avar.name);
		break;
	default:
		fprintf(stderr, "print_entry: bad type %u\n", entry->h.type);
	}

        thelist->append(je);
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
        thelist = JsonList::create();
	while ((r = read_entry(fp, &entry)) > 0)
		handle_entry(&entry);
	if (r < 0)
		die("failed to read entry");
	gzclose(fp);
        thelist->write_to(&cout, 0, nullptr);
	return 0;
}
