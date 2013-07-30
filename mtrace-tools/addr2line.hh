#ifndef _ADDR2LINE_H
#define _ADDR2LINE_H

#include <stdint.h>
#include <string>
#include <vector>

struct line_info
{
    uint64_t pc;
    std::string func, file;
    int line;

    std::string to_string() const;
};

class Addr2line {
private:
    int _out, _in;

public:
    // Construct an address-to-line translator for an ELF binary
    explicit Addr2line(const std::string &path);
    ~Addr2line();

    Addr2line(const Addr2line &o) = delete;
    Addr2line &operator=(const Addr2line &o) = delete;

    // Resolve an address to a sequence of line information
    //
    // Line information for 'pc' will be appended to 'out', from
    // inner-most function to outer-most function (which will differ
    // if 'pc' represents inlined code).  Hence, this can be used to
    // resolve a call stack by calling it repeatedly with each address
    // in the call stack, from inner-most to outer-most.  If 'pc' is
    // inlined, only the first line_info pushed to 'out' will have its
    // 'pc' field set; the rest will have 'pc' set to 0 to indicate
    // that they are inliners.
    void lookup(uint64_t pc, std::vector<line_info> *out) const;

    // Resolve an address to a single line
    //
    // This is like lookup(pc, out), but returns only the inner-most
    // resolution of 'pc'.
    line_info lookup(uint64_t pc) const;
};

#endif // _ADDR2LINE_H
