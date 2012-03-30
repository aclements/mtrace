#ifndef _BININFO_HH_
#define _BININFO_HH_

#include <string>

namespace dwarf { class dwarf; }

/**
 * Translate a type plus an offset into a descriptive string like
 * "(*(type)0x1234).field".  base is the address at which the object
 * starts.  pc, if provided, will be used as a hint to find the
 * compilation unit defining the type.  If pc is omitted or a
 * definition can't be found in pc's compilation unit, all compilation
 * units will be searched for a definition.
 */
std::string
resolve_type_offset(const dwarf::dwarf &dw, const std::string &type,
                    uint64_t base, uint64_t offset, uint64_t pc = 0);

#endif
