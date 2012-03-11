#include <libgen.h>

class ArgParse {
public:
    ArgParse(int ac, char** av)
        : ac_(ac), av_(av), num_long_options_(0) {
        memset(long_options_, 0, sizeof(long_options_));
    }

    void add_option(string option, string val_description, string description) {
        struct option* o;
        int i = num_long_options_++;

        o = &long_options_[i];
        o->name = strdup(option.c_str());
        o->has_arg = 1;
        o->flag = NULL;
        o->val = 0;

        description_[i].val_description = val_description;
        description_[i].description = description;
    }

    void add_option(string option, string description) {
        struct option* o;
        int i = num_long_options_++;

        o = &long_options_[i];
        o->name = strdup(option.c_str());
        o->has_arg = 0;
        o->flag = NULL;
        o->val = 0;

        description_[i].description = description;
    }

    void parse(void (*handle)(const ArgParse* parser,
                              string option,
                              string val)) {
        int c;
        int option_index;

        opterr = 0;
        while (1) {
            c = getopt_long(ac_, av_, "", long_options_, &option_index);
            if (c == -1)
                break;
            else if (c != 0)
                usage("unrecognized option '%s'\n", av_[optind - 1]);

            handle(this, long_options_[option_index].name, optarg != NULL ? optarg : "");
        }
    }

    void __noret__ usage(const char* errstr, ...) const
        __attribute__((format(gnu_printf, 2, 3))) {
        int i;

        if (errstr) {
            va_list ap;

            va_start(ap, errstr);
            vfprintf(stderr, errstr, ap);
            va_end(ap);
        }

        fprintf(stderr, "usage: %s [options]\n\n", basename(av_[0]));

        for (i = 0; i < num_long_options_; i++) {
            string flag;

            flag = long_options_[i].name;
            flag = "--" + flag;
            if (long_options_[i].has_arg)
                flag += "=" + description_[i].val_description;
            
            fprintf(stderr, "  %-22s", flag.c_str());
            fprintf(stderr, " %s\n", description_[i].description.c_str());
        }

        exit(EXIT_FAILURE);
    }

private:
    int                 ac_;
    char**              av_;
    int                 num_long_options_;
    struct option       long_options_[32];

    struct {
        string val_description;
        string description;
    } description_[32];
};
