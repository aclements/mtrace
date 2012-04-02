#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <unordered_map>

#include "bininfo.hh"

#include <dwarf++.hh>

using namespace std;
using namespace dwarf;

static unsigned
get_member_offset(const dwarf::die &node)
{
    return at_data_member_location(node, &dwarf::no_expr_context, 0, 0).value;
}

static void
struct_fields(const dwarf::die &node, map<unsigned, dwarf::die> *fields,
              unsigned additional = 0)
{
    for (auto &mem : node) {
        if (mem.tag == DW_TAG::member) {
            (*fields)[get_member_offset(mem) + additional] = mem;
        } else if (mem.tag == DW_TAG::inheritance) {
            struct_fields(at_type(mem), fields, get_member_offset(mem));
        }
    }
}

static unsigned
type_size(const dwarf::die &node)
{
    if (node.has(DW_AT::byte_size))
        return at_byte_size(node, &dwarf::no_expr_context);

    switch (node.tag) {
    case DW_TAG::typedef_:
    case DW_TAG::const_type:
    case DW_TAG::restrict_type:
    case DW_TAG::volatile_type:
        if (!node.has(DW_AT::type))
            return 0;
        return type_size(at_type(node));

    case DW_TAG::array_type: {
        unsigned elt_size, dimension = 1;
        if (node.has(DW_AT::byte_stride))
            elt_size = at_byte_stride(node, &dwarf::no_expr_context);
        else
            elt_size = type_size(at_type(node));
        for (auto &subrange : node)
            if (subrange.tag == DW_TAG::subrange_type)
                // XXX Not quite right
                dimension *= at_upper_bound(subrange, &dwarf::no_expr_context);
        return elt_size * dimension;
    }

    default:
        return 0;
    }
}

static string
do_offset(const dwarf::die &node, unsigned offset)
{
    switch (node.tag) {
    case DW_TAG::base_type:
    case DW_TAG::enumeration_type:
    case DW_TAG::subroutine_type:
    case DW_TAG::ptr_to_member_type:
    case DW_TAG::pointer_type:
    case DW_TAG::reference_type:
    case DW_TAG::rvalue_reference_type:
        break;

    case DW_TAG::typedef_:
    case DW_TAG::const_type:
    case DW_TAG::restrict_type:
    case DW_TAG::volatile_type:
        if (!node.has(DW_AT::type))
            break;
        return do_offset(at_type(node), offset);

    case DW_TAG::structure_type:
    case DW_TAG::class_type: {
        // Are we within the bounds of this type?
        if (offset >= type_size(node))
            break;

        // Create a map of field offsets
        map<unsigned, dwarf::die> fields;
        struct_fields(node, &fields);

        // Find the field
        auto it(fields.upper_bound(offset));
        if (it == fields.begin())
            break;
        else
            it--;

        // Get the field's type
        dwarf::die ftype(at_type(it->second));

        // Build the return string
        if (!it->second.has(DW_AT::name))
            // Anonymous struct/union
            return ".<anon>" + do_offset(ftype, offset - it->first);
        return "." + at_name(it->second) + do_offset(ftype, offset - it->first);
    }

    case DW_TAG::union_type: {
        string parts;
        for (auto &mem : node) {
            if (mem.tag != DW_TAG::member)
                continue;
            dwarf::die type = at_type(mem);
            if (offset >= type_size(type))
                continue;
            if (!parts.empty())
                parts += '|';
            if (mem.has(DW_AT::name))
                parts += at_name(mem);
            else
                parts += "<anon>";
            parts += do_offset(type, offset);
        }
        if (parts.empty())
            break;
        return ".{" + parts + "}";
    }

    case DW_TAG::array_type: {
        const dwarf::die subtype = at_type(node);
        unsigned elt_size = type_size(subtype);
        if (elt_size == 0)
            break;
        return "[" + to_string(offset / elt_size) + "]" +
            do_offset(subtype, offset % elt_size);
    }

    default:
        return "<do_offset(" + to_string(node.tag) + "@" +
            to_string(node.get_section_offset()) + "," +
            to_string(offset) + ">";
    }

    // Handle a general offset into a base type or a type we couldn't
    // resolve
    if (offset) {
        char buf[64];
        sprintf(buf, "+0x%x", offset);
        return buf;
    }
    return "";
}

// XXX This map will forever keep the entire DWARF file alive.
static unordered_map<die, die_str_map> type_names;

string
resolve_type_offset(const dwarf::dwarf &dw, const string &type,
                    uint64_t base, uint64_t offset,
                    uint64_t pc)
{
    char buf[64];

    for (auto &cu : dw.compilation_units()) {
        const die &root = cu.root();
        if (pc != 0 && !die_pc_range(root).contains(pc))
            continue;

        // Get or create the type name map
        auto tnit = type_names.find(root);
        if (tnit == type_names.end()) {
            type_names[root] = die_str_map::from_type_names(root);
            tnit = type_names.find(root);
        }
        const die_str_map &names = tnit->second;

        // Find this type
        dwarf::die d(names[type]);
        if (!d.valid())
            continue;
        if (d.has(DW_AT::declaration) && at_declaration(d))
            continue;

        // Found our starting point
        sprintf(buf, "%"PRIx64, base);
        return "(*(" + type + ")0x" + buf + ")" + do_offset(d, offset);
    }

    // The pc may not have known what type it was manipulating (e.g.,
    // if doing it through a pointer.  Try again without the pc.
    if (pc != 0)
        return resolve_type_offset(dw, type, base, offset, 0);

    sprintf(buf, "%"PRIx64, offset);
    return type + "+0x" + buf;
}
