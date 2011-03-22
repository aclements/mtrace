#include <stdint.h>
#include <string.h>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}

static inline union mtrace_entry * alloc_entry(void)
{
	return (union mtrace_entry *)malloc(sizeof(union mtrace_entry));
}

static inline void free_entry(void *entry)
{
	free(entry);
}

static inline void init_entry_alloc(void)
{
	// nothing
}

int main(int ac, char **av)
{
	init_entry_alloc();

	if (ac != 2)
		die("usage: %s mtrace-dir mtrace-log", av[0]);
	return 0;
}
