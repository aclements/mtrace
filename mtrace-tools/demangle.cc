#include "demangle.hh"

#include <stdexcept>
#include <cxxabi.h>

static std::string
do_demangle(std::string name)
{
    int status;
    // This is part of the standard IA-64 C++ ABI, but if poking this
    // deeply into the runtime ever becomes an issue, it should be
    // easy to switch to libiberty's demangler.
    char *buf = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
    if (status == 0) {
        std::string res(buf);
        free(buf);
        return res;
    } else if (status == -1) {
        throw std::bad_alloc();
    } else if (status == -2) {
        throw bad_mangled_name(name);
    } else {
        throw std::runtime_error(
            "__cxa_demangle failed with " + std::to_string(status));
    }
}

std::string
demangle(std::string name)
{
    if (name[0] != '_' || name[1] != 'Z')
        return name;
    return do_demangle(name);
}

std::string
demangle_type(std::string name)
{
    if (name[0] == '_' && name[1] == 'Z')
        throw bad_mangled_name(name);
    return do_demangle(name);
}
