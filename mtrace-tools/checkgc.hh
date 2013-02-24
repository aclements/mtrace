#include <map>
#include <vector>
#include <set>
#include <stack>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "percallstack.hh"
#include "bininfo.hh"
#include "physaccess.hh"
#include <dwarf++.hh>

class GcObject {
    uint64_t base;
    uint64_t nbytes;
    char name[64];
};

class CheckGC : public EntryHandler {
public:
    CheckGC() : active_(false) {}

    virtual void handle(const union mtrace_entry* entry) {
        switch (entry->h.type) {
        case mtrace_entry_host:     handle(&entry->host);     break;
        case mtrace_entry_access:   handle(&entry->access);   break;
        case mtrace_entry_gc:       handle(&entry->gc);       break;
        case mtrace_entry_gcepoch:  handle(&entry->gcepoch);  break;
        default:                                              break;
        }
    }

    virtual void exit(JsonDict *json_file) {
        JsonDict* typedict = JsonDict::create();
        for (auto i: reports_by_type_)
            typedict->put(i.first, i.second);
        json_file->put("checkgc", typedict);
    }

private:
    void handle(const mtrace_host_entry* entry) {
        if (entry->host_type == mtrace_access_all_cpu) {
            if (entry->access.mode == mtrace_record_ascope ||
                entry->access.mode == mtrace_record_kernelscope)
            {
                active_ = true;
            }

            if (entry->access.mode == mtrace_record_disable) {
                active_ = false;
            }
        }
    }

    void handle(const mtrace_access_entry* entry) {
        if (!active_)
            return;

        auto it = objects_.lower_bound(entry->guest_addr + entry->bytes);
        if (it == objects_.begin())
            return;

        it--;
        mtrace_gc_entry& gcentry = it->second;
        if (entry->guest_addr >= gcentry.base + gcentry.nbytes)
            return;

        int cpu = entry->h.cpu;
        tid_t tid = mtrace_tid[cpu];
        if (epoch_held_[tid])
            return;

        JsonDict* r = JsonDict::create();
        PhysicalAccess pa;
        pa.access = entry->guest_addr;
        pa.pc = entry->pc;
        pa.size = entry->bytes;
        pa.stack = mtrace_call_trace->get_current(cpu);

        MtraceObject obj;
        if (mtrace_label_map.object(pa.access, obj)) {
            pa.type = obj.name_;
            pa.base = obj.guest_addr_;
        } else {
            pa.base = 0;
        }

        r->put("access", pa.to_json());
        r->put("object_base", gcentry.base);
        r->put("object_bytes", gcentry.nbytes);
        if (reports_by_type_.count(gcentry.name) == 0)
            reports_by_type_[gcentry.name] = JsonList::create();
        reports_by_type_[gcentry.name]->append(r);
    }

    void handle(const mtrace_gc_entry* entry) {
        objects_[entry->base] = *entry;
    }

    void handle(const mtrace_gcepoch_entry* entry) {
        tid_t tid = mtrace_tid[entry->h.cpu];
        epoch_held_[tid] = !!entry->begin;
    }

    bool active_;
    std::map<tid_t, bool> epoch_held_;
    std::map<uint64_t, mtrace_gc_entry> objects_;
    std::map<std::string, JsonList*> reports_by_type_;
};
