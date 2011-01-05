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
}

#include "callstack.hh"
#include "syms.hh"

uint64_t CallTrace::call_interval_count;

using namespace::std;
using namespace::__gnu_cxx;

#define MAX_CPU 4

struct ObjectLabel {

	ObjectLabel(struct mtrace_label_entry *label, 
		    uint64_t access_count_end) 
	{
		this->label_ = label;
		this->access_count_end_ = access_count_end;
	}

	struct mtrace_label_entry *label_;
	uint64_t access_count_end_;
};

struct CompleteFcall {
	CompleteFcall(struct mtrace_fcall_entry *a, struct mtrace_fcall_entry *b) {
		start_ = a;
		stop_ = b;
	}

	struct mtrace_fcall_entry *start_;
	struct mtrace_fcall_entry *stop_;
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

typedef hash_map<uint64_t, struct mtrace_label_entry *> LabelHash;
typedef list<ObjectLabel> 	  		     	ObjectList;
typedef list<struct mtrace_access_entry *> 		AccessList;
typedef list<CompleteFcall> 				FcallList;
typedef hash_map<uint64_t, CallTrace *>  		CallTraceHash;

typedef list<struct mtrace_label_entry *>	     	LabelList;

typedef list< list<CallInterval *> >   			CallIntervalListList;

static LabelHash    outstanding_labels[mtrace_label_end];
static ObjectList   complete_labels[mtrace_label_end];;
static AccessList   accesses;
static FcallList    complete_fcalls;

static LabelList    percpu_labels;

static Syms 	    addr_to_fname;

static CallTrace    *current_stack[MAX_CPU];
static CallTraceHash call_stack;

static CallIntervalListList complete_intervals;

static struct mtrace_enable_entry mtrace_enable;

static void insert_complete_label(ObjectLabel ol)
{
	if (ol.label_->label_type == 0 || 
	    ol.label_->label_type >= mtrace_label_end)
		die("insert_complete_label: bad label type: %u", 
		    ol.label_->label_type);
	complete_labels[ol.label_->label_type].push_back(ol);
}

// In theory, using INTEGER won't yield correct results for a 64-bit virtual 
// address space because INTEGER is a *signed" 64-bit value.  If a label starts 
// at 0x7FFFFFFFFFFFFFFF and is one byte, the end address, 0x8000000000000000, 
// will be a negative number, and smaller than the start address. Lucky for us 
// the AMD64 virtual address space is only 48-bits with a 16-bit sign extension, 
// so this problem never shows up.
//
// Use INTEGER, because it is much faster than BLOB.
// Use BLOB, because it prints much nicer than INTEGER in the sqlite3 shell.

#if 0
#define ADDR_TYPE "BLOB"
#define ADDR_FMT  "x'%016lx'"
#else
#define ADDR_TYPE "INTEGER"
#define ADDR_FMT  "%ld"
#endif

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

static void *open_db(const char *database)
{
	sqlite3 *db;
	int r;

	r = sqlite3_open(database, &db);
	if (r != SQLITE_OK)
		die("sqlite3_open failed");

	exec_stmt(db, NULL, NULL, "PRAGMA synchronous = OFF;");
	exec_stmt(db, NULL, NULL, "PRAGMA count_changes = FALSE;");
	return db;
}

static void build_labelx_db(void *arg, const char *name, 
			    mtrace_label_t label_type)
{
	const char *create_label_table = 
		"CREATE TABLE %s_labels%u ("
		"label_id integer primary key, "
		"str char(32), "
		"alloc_pc "ADDR_TYPE", "
		"host_addr "ADDR_TYPE", "
		"host_addr_end "ADDR_TYPE", "
		"guest_addr "ADDR_TYPE", "
		"guest_addr_end "ADDR_TYPE", "
		"bytes integer, "
		"access_start integer, "
		"access_end integer"
		")";

	const char *insert_label = 
		"INSERT INTO %s_labels%u (str, alloc_pc, "
		"host_addr, host_addr_end, "
		"guest_addr, guest_addr_end, bytes, "
		"access_start, access_end) "
		"VALUES (\"%s\", "ADDR_FMT", "ADDR_FMT", "ADDR_FMT", "
		ADDR_FMT", "ADDR_FMT", %lu, "
		"%lu, %lu)";
	
	const char *create_index = 
		"CREATE INDEX %s_idx_labels%u ON %s_labels%u"
		"(guest_addr, guest_addr_end, access_start, access_end)";

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_labels[label_type].size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_labels%u", 
			name, label_type);
	exec_stmt(db, NULL, NULL, create_label_table, name, label_type);

	ObjectList::iterator it = complete_labels[label_type].begin();
	for (; it != complete_labels[label_type].end(); ++it) {
		ObjectLabel ol = *it;
		
		exec_stmt(db, NULL, NULL, insert_label, name, 
			  label_type, 
			  ol.label_->str, 
			  ol.label_->pc, 			  
			  ol.label_->host_addr, 
			  ol.label_->host_addr + ol.label_->bytes, 
			  ol.label_->guest_addr, 
			  ol.label_->guest_addr + ol.label_->bytes, 
			  ol.label_->bytes, 
			  ol.label_->access_count, 
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
	const char *create_calls_table = 
		"CREATE TABLE %s_call_traces ("
		"call_trace_id integer primary key, "
		"call_trace_tag integer, "
		"cpu integer, "
		"tid "ADDR_TYPE", "
		"pc "ADDR_TYPE", "
		"name VARCHAR(32), "
		"depth integer, "
		"access_start integer, "
		"access_end integer"
		")";

	const char *insert_call = 
		"INSERT INTO %s_call_traces (call_trace_tag, cpu, tid, "
		"pc, name, depth, access_start, access_end) "
		"VALUES (%lu, %u, "ADDR_FMT", "ADDR_FMT", \"%s\", %u, %lu, %lu)";

	const char *create_index[] = {
		"CREATE INDEX %s_idx_calls%u ON %s_call_traces"
		"(cpu, access_start, access_end)",
		"CREATE INDEX %s_idx_calls%u ON %s_call_traces"
		"(cpu, call_trace_tag)" 
	};
		

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_fcalls.size(), 0);
	unsigned int i;

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_call_traces", name);
	exec_stmt(db, NULL, NULL, create_calls_table, name);

	FcallList::iterator it = complete_fcalls.begin();
	for (; it != complete_fcalls.end(); ++it) {
		CompleteFcall cf = (*it);
		const char *fname = addr_to_fname.lookup_name(cf.start_->pc);
		
		if (fname == NULL)
			fname = "(unknown)";

		exec_stmt(db, NULL, NULL, insert_call, name, cf.start_->tag, cf.start_->cpu,
			  cf.start_->tid, cf.start_->pc, fname, cf.start_->depth,
			  cf.start_->access_count, cf.stop_->access_count);

		p.tick();
	}

	for (i = 0; i < sizeof(create_index) / sizeof(create_index[0]); i++)
		exec_stmt(db, NULL, NULL, create_index[i], name, i, name);
}

static void build_call_interval_db(void *arg, const char *name)
{
	const char *create_intervals_table = 
		"CREATE TABLE %s_call_intervals ("
		"id integer PRIMARY KEY, "
		"call_trace_tag INTEGER, "
		"start_pc "ADDR_TYPE", "
		"access_start INTEGER, "
		"access_end INTEGER)";

	const char *insert_interval = 
		"INSERT INTO %s_call_intervals (call_trace_tag, start_pc, "
		"access_start, access_end)"
		"VALUES (%lu, "ADDR_FMT", %lu, %lu)";

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(complete_intervals.size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_call_intervals", name);
	exec_stmt(db, NULL, NULL, create_intervals_table, name);

	CallIntervalListList::iterator it = complete_intervals.begin();
	for (; it != complete_intervals.end(); ++it) {
		list<CallInterval *> ci_list = (*it);

		while (!ci_list.empty()) {
			CallInterval *ci = ci_list.front();
			
			exec_stmt(db, NULL, NULL, insert_interval, name, 
				  ci->call_trace_tag_, 
				  ci->start_pc_,
				  ci->access_start_,
				  ci->access_end_);

			ci_list.pop_front();
			delete ci;
		}

		p.tick();
	}
}

static int get_access_var(void *arg, int ac, char **av, char **colname)
{
	uint64_t *label_id = (uint64_t *)arg;

	if (*label_id != 0)
		die("get_access_var: multiple matching vars?");

	*label_id = strtoll(av[0], NULL, 10);
	return 0;
}

static void get_object(sqlite3 *db, const char *name, 
		       uint64_t access_count, uint64_t guest_addr, 
		       uint64_t* label_id, int* label_type)
{
	const char *select_object = 
		"SELECT label_id FROM %s_labels%u WHERE "
		"guest_addr <= "ADDR_FMT" and guest_addr_end > "ADDR_FMT" and "
		"access_start <= %lu and access_end > %lu";

	int type;

	*label_id = 0;
	for (type = mtrace_label_heap; type < mtrace_label_end; type++) {
		
		exec_stmt(db, get_access_var, (void*)label_id, select_object, 
			  name,
			  type,
			  guest_addr, 
			  guest_addr, 
			  access_count,
			  access_count);

		if (*label_id) {
			*label_type = type;
			return ;
		}
	}
}

static int get_call(void *arg, int ac, char **av, char **colname)
{
	// Call tags are not unique:  
	//   * One function call might generate multiple fcalls that 
	//     have the same tag.
	uint64_t *call_tag = (uint64_t *)arg;
	uint64_t local_call_tag;

	// Multiple matching call tags are ok
	local_call_tag = strtoll(av[0], NULL, 10);
	if (*call_tag && *call_tag != local_call_tag) {
		die("get_call: call_tag mismatch");
	}

	*call_tag = local_call_tag;
	return 0;
}

static void build_access_db(void *arg, const char *name)
{
	const char *create_access_table = 
		"CREATE TABLE %s_accesses ("
		"access_id integer, "
		"access_type integer, "
		"cpu integer, "
		"pc "ADDR_TYPE", "
		"host_addr "ADDR_TYPE", "
		"guest_addr "ADDR_TYPE", "
		"label_id integer, "
		"label_type integer, "
		"call_trace_tag integer"
		")";

	const char *select_call = 
		"SELECT call_trace_tag FROM %s_call_traces WHERE "
		"cpu = %u and "
		"access_start <= %lu and access_end > %lu";

	const char *insert_access = 
		"INSERT INTO %s_accesses ("
		"access_id, access_type, cpu, pc, "
		"host_addr, guest_addr, label_id, label_type, call_trace_tag) "
		"VALUES (%lu, %u, %u, "ADDR_FMT", "ADDR_FMT", "ADDR_FMT", "
		"%lu, %lu, %lu)";

	const char *create_index = 
		"CREATE INDEX %s_idx_accesses ON %s_accesses"
		"(guest_addr)";

	sqlite3 *db = (sqlite3 *) arg;
	Progress p(accesses.size(), 0);

	exec_stmt_noerr(db, NULL, NULL, "DROP TABLE %s_accesses", name);
	exec_stmt(db, NULL, NULL, create_access_table, name);

	while (!accesses.empty()) {
		struct mtrace_access_entry *a = accesses.front();
		uint64_t label_id = 0;
		int label_type = 0;
		uint64_t call_tag = 0;

		get_object(db, name, a->access_count, a->guest_addr,
			   &label_id, &label_type);

		exec_stmt(db, get_call, (void*)&call_tag, select_call, 
			  name,
			  a->cpu, 
			  a->access_count,
			  a->access_count);

		exec_stmt(db, NULL, NULL, insert_access,
			  name,
			  a->access_count, 
			  a->access_type, 
			  a->cpu,
			  a->pc,
			  a->host_addr,
			  a->guest_addr,
			  label_id,
			  label_type,
			  call_tag);

		accesses.pop_front();
		p.tick();
	}

	exec_stmt(db, NULL, NULL, create_index, name, name);
}

static void complete_outstanding_labels(void)
{
	LabelHash* o;
	int i;

	for (i = 1; i < mtrace_label_end; i++) {
		o = &outstanding_labels[i];

		LabelHash::iterator it = o->begin();
		for (; it != o->end(); ++it) {
			struct mtrace_label_entry *l = it->second;
			ObjectLabel ol(l, ~0UL);
			insert_complete_label(ol);
		}
	}
}

static void handle_label(struct mtrace_label_entry *l)
{
	static uint64_t misses[mtrace_label_end];
	LabelHash* o;

	if (l->label_type == 0 || l->label_type >= mtrace_label_end)
	    die("handle_label: bad label type: %u", l->label_type);

	o = &outstanding_labels[l->label_type];
	if (l->bytes) {
		if (o->find(l->guest_addr) != o->end())
			die("oops");
		(*o)[l->guest_addr] = l;
	} else {
		LabelHash::iterator it = o->find(l->guest_addr);
		
		if (it == o->end()) {
			if (mtrace_enable.enable)
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
			if (mtrace_enable.enable || 
			    (it->second->access_count <= 
			     mtrace_enable.access_count))
			{
				ObjectLabel ol(it->second, l->access_count);
				insert_complete_label(ol);
			}
			o->erase(it);
		}
	}
}

static void handle_fcall(struct mtrace_fcall_entry *f)
{
	int cpu = f->cpu;

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

		/* XXX */
		//call_stack.erase(f->tag);
		//delete cs;

		//cs = new CallTrace(f);
		//call_stack[cs->start_->tag] = cs;

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
		cs->end_current(f->access_count);

		current_stack[cpu] = NULL;

		if (mtrace_enable.enable ||
		    cs->start_->access_count <= mtrace_enable.access_count)
		{
			complete_fcalls.push_back(CompleteFcall(cs->start_, f));
		}

		break;
	}
	case mtrace_done: {
		CallTrace *cs;

		if (current_stack[cpu] == NULL)
			die("handle_stack_state: NULL -> start");

		cs = current_stack[cpu];
		cs->end_current(f->access_count);

		call_stack.erase(cs->start_->tag);

		current_stack[cpu] = NULL;

		if (mtrace_enable.enable ||
		    cs->start_->access_count <= mtrace_enable.access_count)
		{
			complete_fcalls.push_back(CompleteFcall(cs->start_, f));
			complete_intervals.push_back(cs->timeline_);
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

	cpu = f->cpu;
	if (cpu >= MAX_CPU)
		die("handle_call: cpu is too large: %u", cpu);

	if (current_stack[cpu] == NULL)
		die("handle_stack_state: NULL -> start");

	cs = current_stack[cpu];

	if (f->ret)
		cs->pop(f);
	else
		cs->push(f);
}

static void handle_access(struct mtrace_access_entry *a)
{
	accesses.push_back(a);
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

static void handle_enable(void *arg, struct mtrace_enable_entry *e)
{
	int old = mtrace_enable.enable;
	memcpy(&mtrace_enable, e, sizeof(mtrace_enable));

	if (old && !mtrace_enable.enable) {
		const char *name = "unknown";
	
		if (mtrace_enable.str[0])
			name = mtrace_enable.str;

		complete_outstanding_labels();

		build_label_db(arg, name);

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
	}
}

static void handle_segment(struct mtrace_segment_entry *seg)
{
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

		ObjectLabel ol(l, ~0UL);
		insert_complete_label(ol);
	}

	// XXX Oops, we leak the mtrace_label_entry in percpu_labels after
	// we handle the final segment.
}

static void process_log(void *arg, union mtrace_entry *entry, unsigned long size)
{
	char *end;

	end = ((char *)entry) + size;

	printf("Scanning log file ...\n");
	fflush(0);
	while ((char *)entry != end) {
		switch(entry->type) {
		case mtrace_entry_label:
			handle_label(&entry->label);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->label));
			break;
		case mtrace_entry_access:
			handle_access(&entry->access);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->access));
			break;
		case mtrace_entry_enable:
			handle_enable(arg, &entry->enable);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->enable));
			break;
		case mtrace_entry_fcall:
			handle_fcall(&entry->fcall);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->fcall));
			break;
		case mtrace_entry_segment:
			handle_segment(&entry->seg);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->seg));
			break;
		case mtrace_entry_call:
			handle_call(&entry->call);
			entry = (union mtrace_entry *)
				(((char *)entry) + sizeof(entry->call));
			break;
		default:
			die("bad type %u", entry->type);
		}
	}

	printf("all done!\n");
}

static void process_symbols(void *arg, const char *nm_file)
{
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

			l->type = mtrace_entry_label;
			l->access_count = 0;
			l->label_type = mtrace_label_static;
			strncpy(l->str, str, sizeof(l->str) - 1);
			l->str[sizeof(l->str) - 1] = 0;
			l->host_addr = 0;
			l->guest_addr = addr;
			l->bytes = size;

			ObjectLabel ol(l, 0x7fffffffffffffffUL);
			insert_complete_label(ol);
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
	ObjectList::iterator it = complete_labels[mtrace_label_static].begin();
	ObjectList::iterator tmp = it;
	++tmp;
	for (; it != complete_labels[mtrace_label_static].end(); it = tmp, ++tmp) {
		ObjectLabel ol = *it;
		if (percpu_start <= ol.label_->guest_addr && 
		    ol.label_->guest_addr < percpu_end)
		{
			complete_labels[mtrace_label_static].erase(it);
			percpu_labels.push_back(ol.label_);
		}
	}

	fclose(f);
	free(line);
	printf("all done!\n");
}

int main(int ac, char **av)
{
	union mtrace_entry *entry;
	struct stat buf;
	void *arg;
	int fd;
	
	if (ac != 4)
		die("usage: %s mtrace-log-file symbol-file database", av[0]);

	fd = open(av[1], O_RDONLY);
	if (fd < 0)
		edie("open %s", av[1]);

	if (fstat(fd, &buf))
		edie("fstat %s", av[1]);

	entry = (union mtrace_entry *)mmap(NULL, buf.st_size, 
					   PROT_READ, MAP_PRIVATE, fd, 0);
	if (entry == MAP_FAILED)
		edie("mmap failed");

	arg = open_db(av[3]);
	process_symbols(arg, av[2]);
	process_log(arg, entry, buf.st_size);
	return 0;
}
