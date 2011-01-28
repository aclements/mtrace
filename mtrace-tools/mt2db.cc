//
// Convert a QEMU mtrace binary file to a SQL database.
//
// Copyright (c) 2010 Silas Boyd-Wickizer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Send feedback to: Silas Boyd-Wickizer <sbw@mit.edu>
//

#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <sqlite3.h>

#include <ext/hash_map>
#include <list>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
#include "sql.h"
}

#include "calltrace.hh"
#include "lockset.hh"
#include "syms.hh"

uint64_t CallTrace::call_interval_count;

using namespace::std;
using namespace::__gnu_cxx;

#define MAX_CPU		4
#define ONE_SHOT 	1

struct Access {
	Access(struct mtrace_access_entry *access, uint64_t call_trace_tag, 
	       uint64_t tid, int label_type, uint64_t label_id) 
	{
		this->access_ = access;
		this->call_trace_tag_ = call_trace_tag;
		this->tid_ = tid;
		this->label_type_ = label_type;
		this->label_id_ = label_id;
	}

	struct mtrace_access_entry *access_;
	uint64_t call_trace_tag_;
	uint64_t tid_;
	int label_type_;
	uint64_t label_id_;
};

struct LockedSection {
	LockedSection(uint64_t lock, int label_type, uint64_t label_id, 
		      uint64_t end_ts, uint64_t tid, CriticalSection *cs)
	{
		lock_ = lock;
		label_type_ = label_type;
		label_id_ = label_id;
		end_ts_ = end_ts;
		tid_ = tid;
		cs_ = *cs;
	}
	uint64_t lock_;
	int label_type_;
	uint64_t label_id_;
	uint64_t end_ts_;
	uint64_t tid_;
	CriticalSection cs_;
};

struct ObjectLabel {

	ObjectLabel(struct mtrace_label_entry *label, uint64_t label_id)
	{
		this->label_ = label;
		this->label_id_ = label_id;

		this->access_count_end_ = 0;
	}

	struct mtrace_label_entry *label_;
	uint64_t label_id_;
	uint64_t access_count_end_;
};

struct CallTraceRange {
	CallTraceRange(struct mtrace_fcall_entry *start, 
			  uint64_t access_stop) 
	{
		start_ = start;
		access_stop_ = access_stop;
	}

	struct mtrace_fcall_entry *start_;
	uint64_t access_stop_;
};

struct Progress {
    
	Progress(unsigned long start, unsigned long end) {
		start_ = start;
		span_ = labs(start - end);
		last_ = start;
	}

	void tick(unsigned long cur) {
		unsigned long a = (10 * labs(last_ - start_)) / span_;
		unsigned long b = (10 * labs(cur - start_)) / span_;
		
		if (a < b) {
			printf("%lu ", b);
			fflush(NULL);
		}
		last_ = cur;
	}
	
	void tick(void) {
		tick(last_ + 1);
	}

	unsigned long last_;
	unsigned long start_;
	unsigned long span_;
};

struct TaskState {
	TaskState(struct mtrace_task_entry *entry) {
		entry_ = entry;
	}

	LockSet lock_set_;
	struct mtrace_task_entry *entry_;
};

typedef map<uint64_t, ObjectLabel>			LabelHash;
typedef list<ObjectLabel> 	  		     	ObjectList;
typedef list<Access> 					AccessList;
typedef list<CallTraceRange> 				CallRangeList;
typedef hash_map<uint64_t, CallTrace *>  		CallTraceHash;
typedef list<struct mtrace_label_entry *>	     	LabelList;
typedef list< list<CallInterval *> >   			CallIntervalList;
typedef hash_map<uint64_t, TaskState *>			TaskTable;
typedef list<LockedSection>	     			LockedSectionList;

static LabelHash    	outstanding_labels[mtrace_label_end];
static ObjectList	complete_labels[mtrace_label_end];;
static AccessList	accesses;
static CallRangeList    complete_fcalls;
static LockedSectionList locked_sections;

static LabelList    	percpu_labels;

static Syms 	    	addr_to_fname;

static CallTrace    	*current_stack[MAX_CPU];
static CallTraceHash 	call_stack;

static CallIntervalList complete_intervals;

static TaskTable	task_table;

static struct mtrace_host_entry mtrace_enable;

static uint64_t 	current_tid[MAX_CPU];

static int should_save_entry(struct mtrace_entry_header *h)
{
	return (mtrace_enable.access.value || 
		h->access_count <= mtrace_enable.h.access_count);
}

static void insert_complete_label(ObjectLabel ol)
{
	if (ol.label_->label_type == 0 || 
	    ol.label_->label_type >= mtrace_label_end)
		die("insert_complete_label: bad label type: %u", 
		    ol.label_->label_type);
	complete_labels[ol.label_->label_type].push_back(ol);
}

static void insert_outstanding_label(struct mtrace_label_entry *l)
{
	static uint64_t label_count;
	uint64_t label_id;
	LabelHash* o;

	if (l->label_type == 0 || l->label_type >= mtrace_label_end)
		die("handle_label: bad label type: %u", l->label_type);

	o = &outstanding_labels[l->label_type];
	if (o->find(l->guest_addr) != o->end())
		die("insert_outstanding_label: overlapping labels");

	label_id = ++label_count;
	(*o).insert(pair<uint64_t, ObjectLabel>(l->guest_addr, ObjectLabel(l, label_id)));
}

static void __attribute__ ((format (printf, 4, 5))) 
exec_stmt(sqlite3 *db, int (*cb)(void*, int, char**, char**),
	  void *arg, const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	char *err;
	int r;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	r = sqlite3_exec(db, buf, cb, arg, &err);
	if (r != SQLITE_OK)
		die("sqlite3_exec failed: %s (%s)", err, buf);
}

static void __attribute__ ((format (printf, 4, 5))) 
exec_stmt_noerr(sqlite3 *db, int (*cb)(void*, int, char**, char**),
		void *arg, const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	
	sqlite3_exec(db, buf, cb, arg, NULL);
}

static void close_db(void *arg)
{
	sqlite3 *db;

	db = (sqlite3 *)arg;
	sqlite3_close(db);
}

static void *open_db(const char *database)
{
	sqlite3 *db;
	int r;

	r = sqlite3_open(database, &db);
	if (r != SQLITE_OK)
		die("sqlite3_open failed");

	exec_stmt(db, NULL, NULL, "PRAGMA synchronous = OFF;");
	exec_stmt(db, NULL, NULL, "PRAGMA count_changes = FALSE;");
	exec_stmt(db, NULL, NULL, "PRAGMA journal_mode = OFF;");
	return db;
}

static void build_labelx_db(void *arg, const char *name, 
			    mtrace_label_t label_type)
{
	const char *create_index = 
		"CREATE INDEX %s_idx_labels%u ON %s_labels%u"
		"(guest_addr, guest_addr_end, access_start, access_end)";

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_labels[label_type].size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_labels%u", 
			name, label_type);
	exec_stmt(db, NULL, NULL, CREATE_LABEL_TABLE, name, label_type);

	ObjectList::iterator it = complete_labels[label_type].begin();
	for (; it != complete_labels[label_type].end(); ++it) {
		ObjectLabel ol = *it;
		
		exec_stmt(db, NULL, NULL, INSERT_LABEL, name, 
			  label_type, 
			  ol.label_id_,
			  ol.label_->str, 
			  ol.label_->pc, 			  
			  ol.label_->host_addr, 
			  ol.label_->host_addr + ol.label_->bytes, 
			  ol.label_->guest_addr, 
			  ol.label_->guest_addr + ol.label_->bytes, 
			  ol.label_->bytes, 
			  ol.label_->h.access_count, 
			  ol.access_count_end_);

		p.tick();
	}

	exec_stmt(db, NULL, NULL, create_index, name, label_type, name, label_type);
}

static void build_label_db(void *arg, const char *name)
{
	int t;

	for (t = 1; t < mtrace_label_end; t++) {
		printf("Building label%u db '%s' ... ", t, name);
		fflush(0);
		build_labelx_db(arg, name, (mtrace_label_t)t);
		printf("done!\n");
	}
}

static void build_call_trace_db(void *arg, const char *name)
{
	const char *create_index[] = {
		"CREATE INDEX %s_idx_calls%u ON %s_call_traces"
		"(cpu, access_start, access_end)",
		"CREATE INDEX %s_idx_calls%u ON %s_call_traces"
		"(cpu, call_trace_tag)",
		"CREATE INDEX %s_idx_calls%u ON %s_call_traces"
		"(call_trace_tag, pc)" 
	};
		

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_fcalls.size(), 0);
	unsigned int i;

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_call_traces", name);
	exec_stmt(db, NULL, NULL, CREATE_CALLS_TABLE, name);

	exec_stmt(db, NULL, NULL, "BEGIN TRANSACTION;");

	CallRangeList::iterator it = complete_fcalls.begin();
	for (; it != complete_fcalls.end(); ++it) {
		CallTraceRange cf = (*it);
		const char *fname = addr_to_fname.lookup_name(cf.start_->pc);
		
		if (fname == NULL)
			fname = "(unknown)";

		exec_stmt(db, NULL, NULL, INSERT_CALL, name, cf.start_->tag, cf.start_->h.cpu,
			  cf.start_->tid, cf.start_->pc, fname, cf.start_->depth,
			  cf.start_->h.access_count, cf.access_stop_);

		p.tick();
	}

	for (i = 0; i < sizeof(create_index) / sizeof(create_index[0]); i++)
		exec_stmt(db, NULL, NULL, create_index[i], name, i, name);

	exec_stmt(db, NULL, NULL, "END TRANSACTION;");
}

static void build_task_db(void *arg, const char *name)
{
	sqlite3 *db = (sqlite3 *) arg;
	Progress p(task_table.size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_tasks", name);
	exec_stmt(db, NULL, NULL, CREATE_TASKS_TABLE, name);

	TaskTable::iterator it = task_table.begin();
	for (; it != task_table.end(); ++it) {
		struct mtrace_task_entry *task = it->second->entry_;

		exec_stmt(db, NULL, NULL, INSERT_TASK, name, 
			  task->tid, task->tgid, task->str);

		delete it->second;
		free(task);
		p.tick();
	}
	task_table.clear();
}

static void build_call_interval_db(void *arg, const char *name)
{
	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_intervals.size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_call_intervals", name);
	exec_stmt(db, NULL, NULL, CREATE_INTERVALS_TABLE, name);

	exec_stmt(db, NULL, NULL, "BEGIN TRANSACTION;");

	CallIntervalList::iterator it = complete_intervals.begin();
	while (!complete_intervals.empty()) {
		list<CallInterval *> ci_list = complete_intervals.front();

		while (!ci_list.empty()) {
			CallInterval *ci = ci_list.front();

			exec_stmt(db, NULL, NULL, INSERT_INTERVAL, name, 
				  ci->id_,
				  ci->call_trace_tag_, 
				  ci->cpu_,
				  ci->start_pc_,
				  ci->end_pc_,
				  ci->access_start_,
				  ci->access_end_,
				  ci->prev_,
				  ci->next_,
				  ci->ret_);

			ci_list.pop_front();
			CallTrace::free_call_interval(ci);
		}

		complete_intervals.pop_front();

		p.tick();
	}

	exec_stmt(db, NULL, NULL, "END TRANSACTION;");
}

static void build_access_db(void *arg, const char *name)
{
	const char *create_index[] = {
		"CREATE INDEX %s_idx_accesses%u ON %s_accesses"
		"(guest_addr)",
		"CREATE INDEX %s_idx_accesses%u ON %s_accesses"
		"(label_id, tid)",
		"CREATE INDEX %s_idx_accesses%u ON %s_accesses"
		"(label_id)",
	};

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(accesses.size(), 0);
	unsigned int i;

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_accesses", name);
	exec_stmt(db, NULL, NULL, CREATE_ACCESS_TABLE, name);
	exec_stmt(db, NULL, NULL, "BEGIN TRANSACTION;");

	while (!accesses.empty()) {
		Access a = accesses.front();

		exec_stmt(db, NULL, NULL, INSERT_ACCESS,
			  name,
			  a.access_->h.access_count, 
			  a.access_->access_type, 
			  a.access_->h.cpu,
			  a.access_->pc,
			  a.access_->host_addr,
			  a.access_->guest_addr,
			  a.label_id_,
			  a.label_type_,
			  a.call_trace_tag_,
			  a.tid_);

		accesses.pop_front();
		p.tick();
	}
	for (i = 0; i < sizeof(create_index) / sizeof(create_index[0]); i++)
		exec_stmt(db, NULL, NULL, create_index[i], name, i, name);

	exec_stmt(db, NULL, NULL, "END TRANSACTION;");
}

static void build_locked_sections_db(void *arg, const char *name)
{
	const char *create_index = 
		"CREATE INDEX %s_idx_locked_sections ON %s_locked_sections"
		"(label_id)";

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(locked_sections.size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_locked_sections", name);
	exec_stmt(db, NULL, NULL, CREATE_LOCKED_SECTIONS_TABLE, name);
	exec_stmt(db, NULL, NULL, "BEGIN TRANSACTION;");

	while (!locked_sections.empty()) {
		LockedSection ls = locked_sections.front();

		exec_stmt(db, NULL, NULL, INSERT_LOCKED_SECTION,
			  name,
			  ls.lock_,
			  ls.label_type_,
			  ls.label_id_,
			  ls.cs_.acquire_ts_,
			  ls.end_ts_,
			  ls.cs_.start_cpu_,
			  ls.cs_.read_mode_,
			  ls.tid_);

		locked_sections.pop_front();
		p.tick();
	}

	exec_stmt(db, NULL, NULL, "END TRANSACTION;");
	exec_stmt(db, NULL, NULL, create_index, name, name);
}

static void build_summary_db(void *arg, const char *name, 
			     struct mtrace_host_entry *start, 
			     struct mtrace_host_entry *end)
{
	sqlite3 *db = (sqlite3 *) arg;

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_summary", name);
	exec_stmt(db, NULL, NULL, CREATE_SUMMARY_TABLE, name);
	exec_stmt(db, NULL, NULL, INSERT_SUMMARY, name,
		  start->h.ts, end->h.ts);
}

static void complete_outstanding_labels(void)
{
	LabelHash* o;
	int i;

	for (i = 1; i < mtrace_label_end; i++) {
		o = &outstanding_labels[i];

		LabelHash::iterator it = o->begin();
		for (; it != o->end(); ++it) {
			ObjectLabel ol = it->second;
			ol.access_count_end_ = MAX_UNSIGNED_INTEGER;
			insert_complete_label(ol);
		}
	}
}

static void handle_label(struct mtrace_label_entry *l)
{
	static uint64_t misses[mtrace_label_end];

	if (l->label_type == 0 || l->label_type >= mtrace_label_end)
	    die("handle_label: bad label type: %u", l->label_type);

	if (l->bytes) {
		insert_outstanding_label(l);
	} else {
		LabelHash* o = &outstanding_labels[l->label_type];
		LabelHash::iterator it = o->find(l->guest_addr);
		
		if (it == o->end()) {
			if (mtrace_enable.access.value)
				die("miss while mtrace enabled");

			// We tolerate a few kfree calls for which we haven't
			// seen a previous kmalloc, because we might have missed
			// the kmalloc before the mtrace kernel code registered
			// the trace functions.
			misses[l->label_type]++;
			if (misses[l->label_type] > 200)
				die("suspicious number of misses %u", 
				    l->label_type);
		} else {
			if (should_save_entry(&it->second.label_->h)) {
				ObjectLabel ol = it->second;
				ol.access_count_end_ = l->h.access_count;
				insert_complete_label(ol);
			}
			o->erase(it);
		}
	}
}

static void complete_outstanding_call_traces(void)
{
#if ONE_SHOT
	CallTraceHash::iterator it = call_stack.begin();

	while (it != call_stack.end()) {
		CallTrace *ct = it->second;

		ct->end_current(MAX_UNSIGNED_INTEGER, 0);

		// We already accounted for the CallTraceRange when we 
		// processed the mtrace_pause.  The call intervals are 
		// what's left.
		complete_intervals.push_back(ct->timeline_);
		
		delete ct;

		call_stack.erase(it);
		it = call_stack.begin();		
	}
#else
	// XXX if we aren't in ONE_SHOT mode complete_outstanding_call_traces
	// ends up destroying outstanding call traces (and timelines).
#error complete_outstanding_call_traces is broken
#endif
}

static void handle_fcall(struct mtrace_fcall_entry *f)
{
	int cpu = f->h.cpu;

	if (cpu >= MAX_CPU)
		die("handle_fcall: cpu is too large: %u", cpu);

	switch (f->state) {
	case mtrace_resume: {
		CallTraceHash::const_iterator it;
		CallTrace *cs;

		if (current_stack[cpu] != NULL)
			die("handle_stack_state: start -> resume");

		it = call_stack.find(f->tag);
		if (it == call_stack.end())
			die("handle_stack_state: unable to find %lu", f->tag);

		cs = it->second;

		cs->start_ = f;

		current_stack[cpu] = cs;
		break;
	}
	case mtrace_start: {
		CallTrace *cs;

		if (current_stack[cpu] != NULL)
			die("handle_stack_state: start -> start");

		cs = new CallTrace(f);
		call_stack[cs->start_->tag] = cs;
		current_stack[cpu] = cs;

		break;
	}
	case mtrace_pause: {
		CallTrace *cs;

		if (current_stack[cpu] == NULL)
			die("handle_stack_state: NULL -> pause %lu", f->tag);

		cs = current_stack[cpu];
		cs->end_current(f->h.access_count, 0);

		current_stack[cpu] = NULL;

		if (should_save_entry(&cs->start_->h))
			complete_fcalls.push_back(CallTraceRange(cs->start_, f->h.access_count));

		break;
	}
	case mtrace_done: {
		CallTrace *cs;

		if (current_stack[cpu] == NULL)
			die("handle_stack_state: NULL -> done");

		cs = current_stack[cpu];
		cs->end_current(f->h.access_count, 0);

		call_stack.erase(cs->start_->tag);

		current_stack[cpu] = NULL;

		if (should_save_entry(&cs->start_->h)) {
			complete_fcalls.push_back(CallTraceRange(cs->start_, f->h.access_count));
			complete_intervals.push_back(cs->timeline_);
		} else {
			cs->free_timeline();
		}

		delete cs;
		break;
	}
	default:
		die("handle_stack_state: bad state %u", f->state);		
	}
}

static void handle_call(struct mtrace_call_entry *f)
{
	CallTrace *cs;
	int cpu;

	cpu = f->h.cpu;
	if (cpu >= MAX_CPU)
		die("handle_call: cpu is too large: %u", cpu);

	if (current_stack[cpu] == NULL)
		die("handle_stack_state: NULL -> start");

	cs = current_stack[cpu];

	if (should_save_entry(&f->h)) {
		if (f->ret)
			cs->pop(f);
		else
			cs->push(f);
	} 
	free(f);
}

static int get_object(uint64_t guest_addr, int *label_type, uint64_t *label_id)
{
	int t;

	for (t = 1; t < mtrace_label_end; t++) {
		struct mtrace_label_entry *label;
		LabelHash::iterator it;
		LabelHash *lh;

		lh = &outstanding_labels[t];
		it = lh->lower_bound(guest_addr);

		if (it != lh->begin()) {
			if (it != lh->end()) {
				label = it->second.label_;
				if (label->guest_addr == guest_addr)
					goto found;
				--it;
			} else {
				--it;
			}
		}

		label = it->second.label_;		
		if (label->guest_addr <= guest_addr && 
		    guest_addr < label->guest_addr + label->bytes)
		{
			goto found;
		}

		continue;
	found:
		*label_type = t;
		*label_id = it->second.label_id_;
		return 1;
	}

	*label_type = 0;
	*label_id = 0;
	return 0;
}

static void handle_access(struct mtrace_access_entry *a)
{
	uint64_t call_trace_tag = ~0UL;
	uint64_t label_id = 0;
	int label_type = 0;
	uint64_t tid = ~0UL;
	
	if (current_stack[a->h.cpu]) {
		CallTrace *cs = current_stack[a->h.cpu];
		call_trace_tag = cs->start_->tag;
		tid = cs->start_->tid;
	}

	get_object(a->guest_addr, &label_type, &label_id);
	accesses.push_back(Access(a, call_trace_tag, tid, label_type, label_id));
}

static void clear_all(void)
{
	int t;	
	complete_fcalls.clear();

	for (t = 1; t < mtrace_label_end; t++) {
		if (t != mtrace_label_static && t != mtrace_label_percpu)
			complete_labels[t].clear();
	}
}

static void handle_host(void *arg, struct mtrace_host_entry *e)
{
	struct mtrace_host_entry old;

	if (e->host_type == mtrace_call_clear_cpu ||
	    e->host_type == mtrace_call_set_cpu) 
	{
		free(e);
		return;
	} else if (e->host_type != mtrace_access_all_cpu)
		die("handle_host: unhandled type %u", e->host_type);

	old = mtrace_enable;
	mtrace_enable = *e;

	if (old.access.value && !mtrace_enable.access.value) {
		const char *name = "unknown";
	
		if (mtrace_enable.access.str[0])
			name = mtrace_enable.access.str;

		complete_outstanding_labels();
		complete_outstanding_call_traces();

		build_summary_db(arg, name, &old, &mtrace_enable);

		build_label_db(arg, name);

		printf("Building locked_sections db '%s' ...", name);
		fflush(0);
		build_locked_sections_db(arg, name);
		printf("done!\n");

		printf("Building tasks db '%s' ... ", name);
		fflush(0);
		build_task_db(arg, name);
		printf("done!\n");

		printf("Building call_traces db '%s' ... ", name);
		fflush(0);
		build_call_trace_db(arg, name);
		printf("done!\n");

		printf("Building call_intervals db '%s' ... ", name);
		fflush(0);
		build_call_interval_db(arg, name);
		printf("done!\n");

		printf("Building access db '%s' ... ", name);
		fflush(0);
		build_access_db(arg, name);
		printf("done!\n");

		clear_all();

		if (ONE_SHOT) {
			close_db(arg);
			exit(EXIT_SUCCESS);
		}
	}
}

static void handle_segment(struct mtrace_segment_entry *seg)
{
#if ONE_SHOT
	if (seg->object_type != mtrace_label_percpu)
		die("handle_segment: bad type %u", seg->object_type);

	LabelList::iterator it = percpu_labels.begin();
	for (; it != percpu_labels.end(); ++it) {
		struct mtrace_label_entry *offset = *it;
		struct mtrace_label_entry *l = 
			(struct mtrace_label_entry *) malloc(sizeof(*l));

		memcpy(l, offset, sizeof(*l));
		l->guest_addr = seg->baseaddr + offset->guest_addr;
		l->label_type = mtrace_label_percpu;

		if (l->guest_addr + l->bytes > seg->endaddr)
			die("handle_segment: bad label: %s", l->str);

		insert_outstanding_label(l);
	}

	// XXX Oops, we leak the mtrace_label_entry in percpu_labels after
	// we handle the final segment.
#else
	// XXX by adding to outstanding_labels the per_cpu labels will
	// disappear when complete_oustanding labels is called.
#error handle_segment is broken
#endif
}

static void handle_task(struct mtrace_task_entry *task)
{
	if (task->task_type == mtrace_task_init) {
		TaskTable::iterator it = task_table.find(task->tid);

		if (it != task_table.end()) {
			if (mtrace_enable.access.value)
				die("handle_task: Oops, reused TID");
			free(it->second->entry_);
			it->second->entry_ = task;
		} else {
			task_table[task->tid] = new TaskState(task);
		}
	} else if (task->task_type == mtrace_task_update) {
		TaskState *cur;

		if (task_table.find(task->tid) == task_table.end())
			die("handle_task: Oops, missing task");

		cur = task_table[task->tid];
		// str is the only thing that might change
		strcpy(cur->entry_->str, task->str);
		free(task);
	} else if (task->task_type == mtrace_task_exit) {
		TaskTable::iterator it = task_table.find(task->tid);
		TaskState *ts;

		if (it == task_table.end())
			die("handle_task: Oops, missing task exited");

		ts = it->second;
		task_table.erase(it);
		free(ts->entry_);
		delete ts;
	}
}

static void handle_sched(struct mtrace_sched_entry *sched)
{
	int cpu = sched->h.cpu;

	if (cpu >= MAX_CPU)
		die("handle_task: cpu is too large %u", cpu);

	current_tid[cpu] = sched->tid;
	free(sched);
}

static void handle_lock(struct mtrace_lock_entry *lock)
{
	TaskState *ts;
	int cpu = lock->h.cpu;
	uint64_t tid;

	if (!should_save_entry(&lock->h)) {
	    free(lock);
	    return;
	}

	if (cpu >= MAX_CPU)
		die("handle_lock: cpu is too large %u", cpu);

	tid = current_tid[cpu];
	if (tid == 0) {
		// The kernel acquires locks before mm/mtrace.c
		// registers its tracers.
		//die("handle_lock: no TID");
		free(lock);
		return;
	}

	TaskTable::iterator it = task_table.find(tid);	
	if (it == task_table.end()) {
		// The kernel acquires locks before mm/mtrace.c
		// registers its tracers.
		if (mtrace_enable.access.value)
			die("handle_lock: no task for TID %lu", tid);
		free(lock);
		return;
	}

	ts = it->second;

	switch (lock->op) {
	case mtrace_lockop_release: {
		CriticalSection cs;
		if (ts->lock_set_.release(lock, &cs)) {
			int label_type;
			uint64_t label_id;
			
			get_object(lock->lock, &label_type, &label_id);
			locked_sections.push_back(LockedSection(lock->lock,
								label_type,
								label_id,
								lock->h.ts,
								tid,
								&cs));
		}
		break;
	}
	case mtrace_lockop_acquire:	
		ts->lock_set_.acquire(lock);
		break;
	case mtrace_lockop_acquired:
		ts->lock_set_.acquired(lock);
		break;
	default:
		die("handle_lock: bad op %u", lock->op);
	}

	free(lock);
}

static void process_log(void *arg, gzFile log)
{
	union mtrace_entry *entry;
	int r;

	// XXX temp fix.
	entry = (union mtrace_entry *)malloc(sizeof(*entry));

	printf("Scanning log file ...\n");
	fflush(0);
        while ((r = read_entry(log, entry)) > 0) {
		switch(entry->h.type) {
		case mtrace_entry_label:
			handle_label(&entry->label);
			break;
		case mtrace_entry_access:
			handle_access(&entry->access);
			break;
		case mtrace_entry_host:
			handle_host(arg, &entry->host);
			break;
		case mtrace_entry_fcall:
			handle_fcall(&entry->fcall);
			break;
		case mtrace_entry_segment:
			handle_segment(&entry->seg);
			break;
		case mtrace_entry_call:
			handle_call(&entry->call);
			break;
		case mtrace_entry_lock:
			handle_lock(&entry->lock);
			break;
		case mtrace_entry_sched:
			handle_sched(&entry->sched);
			break;
		case mtrace_entry_task:
			handle_task(&entry->task);
			break;
		default:
			die("bad type %u", entry->h.type);
		}

		// XXX temp fix.
		entry = (union mtrace_entry *)malloc(sizeof(*entry));
	}
	if (r < 0)
		die("failed to read log file");
	printf("all done!\n");
}

static void process_symbols(void *arg, const char *nm_file)
{
	list<struct mtrace_label_entry *> tmp;
	uint64_t addr;
	uint64_t size;
	uint64_t percpu_start;
	uint64_t percpu_end;
	char str[128];
	char* line = NULL;
	char type;
	FILE *f;
	int r;
	size_t len;

	percpu_start = 0;
	percpu_end = 0;

	f = fopen(nm_file, "r");
	if (f == NULL)
		edie("fopen %s failed", nm_file);

	printf("Processing nm file ...");
	fflush(0);

	while (getline(&line, &len, f) != -1) {
		r = sscanf(line, "%lx %lx %c %s", &addr, &size, &type, &str);
		if (r == 4 && (type == 'D' || type == 'd' || // .data
			       type == 'B' || type == 'b' || // .bbs
			       type == 'r' || type == 'R' || // .ro
			       type == 'A'))  	      	     // absolute
		{
			struct mtrace_label_entry *l = 
				(struct mtrace_label_entry *) malloc(sizeof(*l));

			l->h.type = mtrace_entry_label;
			l->h.access_count = 0;
			l->label_type = mtrace_label_static;
			strncpy(l->str, str, sizeof(l->str) - 1);
			l->str[sizeof(l->str) - 1] = 0;
			l->host_addr = 0;
			l->guest_addr = addr;
			l->bytes = size;

			tmp.push_back(l);
			continue;
		}

		if (r == 4 && (type == 'T' || type == 't')) { // .text
			addr_to_fname.insert_sym(addr, size, str);
			continue;
		}
		
		r = sscanf(line, "%lx %c %s", &addr, &type, &str);
		if (r == 3 && type == 'D') {
			if (!strcmp("__per_cpu_end", str)) {
				percpu_end = addr;
			} else if (!strcmp("__per_cpu_start", str)) {
				percpu_start = addr;
			}
			continue;
		}
	}

	if (errno)
		edie("getline %s failed", nm_file);

	// Move all the labels for percpu variables from the mtrace_label_static 
	// list to the temporary list.  Once we know each CPUs percpu base 
	// address we add percpu objects onto the mtrace_label_percpu list.
	list<struct mtrace_label_entry *>::iterator it = tmp.begin();
	list<struct mtrace_label_entry *>::iterator next = it;
	++next;
	for (; it != tmp.end(); it = next, ++next) {
		struct mtrace_label_entry *l = *it;
		if (percpu_start <= l->guest_addr && l->guest_addr < percpu_end)
			percpu_labels.push_back(l);
		else
			insert_outstanding_label(l);
	}

	fclose(f);
	free(line);
	printf("all done!\n");
}

int main(int ac, char **av)
{
	void *arg;
        gzFile log;

	if (ac != 4)
		die("usage: %s mtrace-log-file symbol-file database", av[0]);

        log = gzopen(av[1], "rb");
        if (!log)
		edie("gzopen %s", av[1]);

	arg = open_db(av[3]);
	process_symbols(arg, av[2]);
	process_log(arg, log);
	return 0;
}
