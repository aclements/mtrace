#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <zlib.h>
#include <mtrace-magic.h>

#define __noret__ __attribute__((noreturn))
#define __chfmt__ __attribute__ ((format (printf, 1, 2)))

static void __noret__ __chfmt__ die(const char* errstr, ...) 
{
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static void __noret__ __chfmt__ edie(const char* errstr, ...) 
{
        va_list ap;

        va_start(ap, errstr);
        vfprintf(stderr, errstr, ap);
        va_end(ap);
        fprintf(stderr, ": %s\n", strerror(errno));
        exit(EXIT_FAILURE);
}

__attribute__((__used__))
static int read_entry(gzFile fp, union mtrace_entry *entry_out)
{
	size_t r, left;
	r = gzread(fp, entry_out, sizeof(entry_out->h));
	if (r != sizeof(entry_out->h))
		return r == 0 ? 0 : -1;
	if (entry_out->h.size > sizeof(*entry_out))
		die("entry too big: %u > %u",
		    (unsigned)entry_out->h.size, (unsigned)sizeof(*entry_out));
	left = entry_out->h.size - sizeof(entry_out->h);
	r = gzread(fp, ((char*)entry_out) + sizeof(entry_out->h), left);
	if (r != left)
		return -1;
	return 1;
}
