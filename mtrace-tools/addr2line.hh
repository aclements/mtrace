#ifndef _ADDR2LINE_H
#define _ADDR2LINE_H

#include <stdint.h>

class Addr2line {
private:
    int _out, _in;

public:
    explicit Addr2line(const char* path);
    ~Addr2line();
    int lookup(uint64_t pc, char** func, char** file, int* line) const;
};

#endif // _ADDR2LINE_H
