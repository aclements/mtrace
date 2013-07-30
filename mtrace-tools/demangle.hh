#ifndef _DEMANGLE_H
#define _DEMANGLE_H

#include <string>
#include <stdexcept>

// Demangle a function or data object name.
//
// May through bad_alloc, bad_mangled_name, or runtime_error.
std::string demangle(std::string name);

// Demangle a type name.
//
// May through bad_alloc, bad_mangled_name, or runtime_error.
std::string demangle_type(std::string name);

// Exception reporting a malformed mangled name.
class bad_mangled_name : public std::invalid_argument
{
public:
    explicit bad_mangled_name(const std::string& what_arg)
        : invalid_argument(what_arg) { }
    explicit bad_mangled_name(const char* what_arg)
        : invalid_argument(what_arg) { }
};

#endif // _DEMANGLE_H
