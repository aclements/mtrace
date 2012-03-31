#include <libgen.h>
#include "util.h"

int main(int ac, char **av)
{
    if (ac == 3 && strcmp(av[1], "movement") == 0)
        mtrace_enable_set(mtrace_record_movement, av[2]);
    else if (ac == 3 && strcmp(av[1], "ascope") == 0)
        mtrace_enable_set(mtrace_record_ascope, av[2]);
    else if (ac == 3 && strcmp(av[1], "disable") == 0)
        mtrace_enable_set(mtrace_record_disable, av[2]);
    else {
        fprintf(stderr, "usage: %s movement|ascope|disable name", basename(av[0]));
        return 2;
    }
    return 0;
}
