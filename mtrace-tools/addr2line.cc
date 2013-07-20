#include "addr2line.hh"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include <sstream>
#include <system_error>

static const char* addr2line_exe[] = {
    "addr2line",
    "x86_64-jos-elf-addr2line",
};

static void
throw_errno()
{
    throw std::system_error(errno, std::system_category());
}

std::string
line_info::to_string() const
{
    std::stringstream ss;
    ss << func << " at " << file << ":" << line;
    if (pc && func[0] != '0')
        ss << " (0x" << std::hex << pc << ")";
    return ss.str();
}

Addr2line::Addr2line(const char* path)
{
    int out[2], in[2], check[2], child, r;

    if (pipe(out) < 0 || pipe(in) < 0 || pipe(check) < 0)
        throw_errno();
    if (fcntl(check[1], F_SETFD,
              fcntl(check[1], F_GETFD, 0) | FD_CLOEXEC) < 0)
        throw_errno();

    child = fork();
    if (child < 0) {
        throw_errno();
    } else if (child == 0) {
        unsigned int i;

        close(check[0]);
        dup2(out[0], 0);
        close(out[0]);
        close(out[1]);
        dup2(in[1], 1);
        close(in[0]);
        close(in[1]);

        for (i = 0; i < sizeof(addr2line_exe) / sizeof(addr2line_exe[0]); i++)
            r = execlp(addr2line_exe[i], addr2line_exe[i],
                       "-C", "-f", "-s", "-i", "-e", path, NULL);
        r = 1;
        r = write(check[1], &r, sizeof(r));
        assert(sizeof(r) == r);
        exit(0);
    }
    close(out[0]);
    close(in[1]);
    close(check[1]);

    if (read(check[0], &r, sizeof(r)) != 0) {
        errno = r;
        throw_errno();
    }
    close(check[0]);

    _out = out[1];
    _in = in[0];
}

Addr2line::~Addr2line()
{
    close(_in);
    close(_out);
}

void
Addr2line::lookup(uint64_t pc, std::vector<line_info> *out) const
{
    char buf[4096];

    // We add a dummy request so we can detect the end of the inline
    // sequence.  The response will look like "??\n??:0\n".  If we ask
    // for an unknown PC, we'll also get this response, but it will be
    // the first response, so we know it's a real response.
    int n = snprintf(buf, sizeof(buf), "%#" PRIx64 "\n\n", pc);
    if (n != write(_out, buf, n))
        throw_errno();

    n = 0;
    while (1) {
        int r = read(_in, buf + n, sizeof(buf) - n - 1);
        if (r < 0)
            throw_errno();
        n += r;
        buf[n] = 0;

        // Have we seen the dummy response?
        char *end = strstr(buf + 1, "??\n??:0\n");
        if (end) {
            *end = 0;
            break;
        }
    }

    char *pos = buf;
    while (*pos) {
        char* nl, *col, *end;
        line_info li;
        li.pc = (pos == buf ? pc : 0);
        nl = strchr(pos, '\n');
        li.func = std::string(pos, nl - pos);
        if (li.func == "??") {
            // Replace this with something more useful
            std::stringstream ss;
            ss << "0x" << std::hex << pc;
            li.func = ss.str();
        }
        col = strchr(nl, ':');
        if (!col)
            throw std::runtime_error("Missing ':' in addr2line output");
        li.file = std::string(nl + 1, col - nl - 1);
        end = NULL;
        li.line = strtol(col + 1, &end, 10);
        if (!end || *end != '\n')
            throw std::runtime_error
                ("Malformed line number in addr2line output");
        out->push_back(li);
        pos = end + 1;
    }
}

line_info
Addr2line::lookup(uint64_t pc) const
{
    std::vector<line_info> vec;
    lookup(pc, &vec);
    // We should always at least get the "??" response
    assert(!vec.empty());
    return vec[0];
}
