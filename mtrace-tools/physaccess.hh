#pragma once

struct PhysicalAccess {
    string type;
    uint64_t base;
    uint64_t access;
    uint64_t pc;
    uint8_t size;
    const CallTrace::CallStack *stack;

    JsonDict *to_json(const PhysicalAccess *other = nullptr) const
    {
        JsonDict *out = JsonDict::create();
        if (type.size()) {
            // XXX For static symbols, we only have the name of
            // the symbol, not the name of its type.
            out->put("addr", resolve_type_offset(mtrace_dwarf, type, base, access - base, pc));
            if (other && other->type.size() && other->type != type)
              out->put("addr2", resolve_type_offset(mtrace_dwarf, type, base, access - base, pc));
        } else {
            out->put("addr", new JsonHex(access));
        }
        out->put("rawaddr", new JsonHex(access));
        if (other && pc != other->pc) {
            out->put("pc1", addr2line->lookup(pc).to_string());
            out->put("pc2", addr2line->lookup(other->pc).to_string());
        } else {
            out->put("pc", addr2line->lookup(pc).to_string());
        }
        out->put("size", size);

        if (other) {
            if (stack && other->stack) {
                if (*stack == *other->stack) {
                    out->put("stack", stack->new_json_short(pc));
                } else {
                    out->put("stack1", stack->new_json_short(pc));
                    out->put("stack2", other->stack->new_json_short(other->pc));
                }
            }
        } else if (stack) {
            out->put("stack", stack->new_json_short(pc));
        }

        return out;
    }

    bool operator<(const PhysicalAccess &o) const
    {
        return access < o.access;
    }
};
