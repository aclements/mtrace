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
