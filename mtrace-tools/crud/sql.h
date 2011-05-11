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

#define MAX_UNSIGNED_INTEGER 0x7fffffffffffffffUL

/* 
 * accesses 
 */
#define CREATE_ACCESS_TABLE						\
	"CREATE TABLE %s_accesses ("					\
	"access_id    		  INTEGER, "				\
	"access_type 		  INTEGER, "				\
	"cpu 			  INTEGER, "				\
	"pc 			  "ADDR_TYPE", "			\
	"host_addr 		  "ADDR_TYPE", "			\
	"guest_addr 		  "ADDR_TYPE", "			\
	"label_id 		  INTEGER, "   				\
	"label_type 		  INTEGER, "				\
	"call_trace_tag 	  INTEGER, "				\
	"tid			  INTEGER, " 				\
	"locked_id		  INTEGER, " 				\
	"traffic		  INTEGER, " 				\
	"locked_inst		  INTEGER" 				\
	")"

#define INSERT_ACCESS							\
	"INSERT INTO %s_accesses ("					\
	"access_id, access_type, cpu, pc, "				\
	"host_addr, guest_addr, label_id, label_type, call_trace_tag, " \
	"tid, locked_id, traffic, locked_inst) "		      	\
	"VALUES (%lu, %u, %u, "ADDR_FMT", "ADDR_FMT", "ADDR_FMT", "   	\
	"%lu, %u, %lu, %lu, %lu, %u, %u)"

/*
 * labels
 */
#define CREATE_LABEL_TABLE						\
    	"CREATE TABLE %s_labels%u ("					\
	"label_id     	     INTEGER PRIMARY KEY, "			\
	"str 		     CHAR(32), "     	  			\
	"alloc_pc 	     "ADDR_TYPE", "				\
	"host_addr 	     "ADDR_TYPE", "				\
	"host_addr_end 	     "ADDR_TYPE", "				\
	"guest_addr 	     "ADDR_TYPE", "				\
	"guest_addr_end      "ADDR_TYPE", "				\
	"bytes 		     INTEGER, "	  				\
	"access_start 	     INTEGER, "					\
	"access_end 	     INTEGER" 					\
	")"

#define INSERT_LABEL							\
    	"INSERT INTO %s_labels%u (label_id, str, alloc_pc, "		\
	"host_addr, host_addr_end, "	    	 	   		\
	"guest_addr, guest_addr_end, bytes, "				\
	"access_start, access_end) " 	    				\
	"VALUES (%lu, \"%s\", "ADDR_FMT", "ADDR_FMT", "ADDR_FMT", "	\
	ADDR_FMT", "ADDR_FMT", %lu, "	  	      		  	\
	"%lu, %lu)"

/*
 * tasks
 */
#define CREATE_TASKS_TABLE						\
	"CREATE TABLE %s_tasks ("					\
	"tid 	      	   INTEGER primary key, "			\
	"tgid    	   INTEGER, "	   				\
	"str 		   CHAR(32)"					\
	")"

#define INSERT_TASK							\
	"INSERT INTO %s_tasks (tid, tgid, str) "			\
	"VALUES (%lu, %lu, \"%s\")"

/*
 * call stacks/traces
 */
#define CREATE_CALLS_TABLE						\
    	"CREATE TABLE %s_call_traces ("					\
	"call_trace_id 	   INTEGER primary key, "			\
	"call_trace_tag    INTEGER, "	   				\
	"cpu 		   INTEGER, "					\
	"tid 		   "ADDR_TYPE", "				\
	"pc 		   "ADDR_TYPE", "				\
	"name 		   VARCHAR(32), "				\
	"depth 		   INTEGER, "					\
	"access_start 	   INTEGER, "					\
	"access_end 	   INTEGER" 					\
	")"

#define INSERT_CALL							\
    	"INSERT INTO %s_call_traces (call_trace_tag, cpu, tid, "	\
	"pc, name, depth, access_start, access_end) "	       		\
	"VALUES (%lu, %u, "ADDR_FMT", "ADDR_FMT", \"%s\", %u, %lu, %lu)"

/*
 * call intervals
 */
#define CREATE_INTERVALS_TABLE						\
	"CREATE TABLE %s_call_intervals ("				\
	"id 	      	INTEGER PRIMARY KEY, "				\
	"call_trace_tag INTEGER, "	     				\
	"cpu 		INTEGER, "					\
	"start_pc 	"ADDR_TYPE", "					\
	"end_pc 	"ADDR_TYPE", "					\
	"access_start 	INTEGER, "   					\
	"access_end 	INTEGER, "					\
	"prev_id	INTEGER, "					\
	"next_id	INTEGER, "					\
	"ret_id		INTEGER" 					\
	")"

#define INSERT_INTERVAL							\
	"INSERT INTO %s_call_intervals (id, call_trace_tag, cpu, "	\
	"start_pc, end_pc, access_start, access_end, prev_id, "	 	\
	"next_id, ret_id) "		 	     	      		\
	"VALUES (%lu, %lu, %u, "ADDR_FMT", "ADDR_FMT", %lu, %lu, "	\
	"%lu, %lu, %lu)"

/* 
 * locked sections
 */
#define CREATE_LOCKED_SECTIONS_TABLE					\
	"CREATE TABLE %s_locked_sections ("				\
	"id    		  	  INTEGER PRIMARY KEY, "		\
	"str			  CHAR(32), "	       			\
	"lock 		  	  "ADDR_TYPE", "			\
	"pc 		  	  "ADDR_TYPE", "			\
	"label_type 		  INTEGER, "				\
	"label_id 		  INTEGER, "   				\
	"start_ts 		  INTEGER, "				\
	"end_ts 	  	  INTEGER, "				\
	"start_cpu		  INTEGER, "				\
	"read			  INTEGER, "				\
	"tid			  INTEGER, " 				\
	"call_trace_tag		  INTEGER, "				\
	"locked_accesses	  INTEGER, "				\
	"traffic_accesses	  INTEGER" 				\
	")"

#define INSERT_LOCKED_SECTION						\
	"INSERT INTO %s_locked_sections ("				\
	"id, str, lock, pc, label_type, label_id, start_ts, "		\
	"end_ts, start_cpu, read, locked_accesses, traffic_accesses, "	\
	"call_trace_tag, tid) "						\
	"VALUES (%lu, \"%s\", "ADDR_FMT", "ADDR_FMT", %u, %lu, %lu, "	\
	"%lu, %u, %u, %lu, %lu, %lu, %lu)"

#if MAX_CPU > 4
#error Too many CPUs for summary table schema 
#endif

/*
 * summary
 */
#define CREATE_SUMMARY_TABLE						\
    	"CREATE TABLE %s_summary ("					\
	"num_cpus     		 INTEGER, "				\
	"num_ram		 INTEGER, "				\
	"start_ts     		 INTEGER, "				\
	"end_ts			 INTEGER, " 				\
	"spin_cycles		 INTEGER, "				\
	"spin_locked_accesses	 INTEGER, "				\
	"spin_traffic_accesses	 INTEGER, "				\
	"locked_accesses	 INTEGER, "				\
	"traffic_accesses	 INTEGER, "				\
	"lock_acquires		 INTEGER, "				\
	"num_ops		 INTEGER" 				\
	")"

#define INSERT_SUMMARY							\
    	"INSERT INTO %s_summary ("					\
	"num_cpus, num_ram, start_ts, end_ts, spin_cycles, "		\
	"spin_locked_accesses, spin_traffic_accesses, "	   		\
	"locked_accesses, traffic_accesses, lock_acquires, num_ops)"  	\
	"VALUES (%u, %lu, %lu, %lu, %lu, %lu, %lu, %lu, " 		\
	"%lu, %lu, %lu)"
