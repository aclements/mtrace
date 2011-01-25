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
	"tid			  INTEGER" 				\
	")"

#define INSERT_ACCESS							\
	"INSERT INTO %s_accesses ("					\
	"access_id, access_type, cpu, pc, "				\
	"host_addr, guest_addr, label_id, label_type, call_trace_tag, " \
	"tid) "     			  	      		      	\
	"VALUES (%lu, %u, %u, "ADDR_FMT", "ADDR_FMT", "ADDR_FMT", "   	\
	"%lu, %u, %lu, %lu)"

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
