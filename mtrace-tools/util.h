#include <stdio.h>
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

static int read_entry(gzFile fp, union mtrace_entry *entryOut)
{
	size_t r, left;
	r = gzread(fp, entryOut, sizeof entryOut->h);
	if (r != sizeof entryOut->h)
		return r == 0 ? 0 : -1;
	if (entryOut->h.size > sizeof *entryOut)
		die("entry too big: %u > %u",
		    (unsigned)entryOut->h.size, (unsigned)sizeof *entryOut);
	left = entryOut->h.size - sizeof entryOut->h;
	r = gzread(fp, ((char*)entryOut) + sizeof entryOut->h, left);
	if (r != left)
		return -1;
	return 1;
}
