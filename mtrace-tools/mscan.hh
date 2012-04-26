#ifndef _MSCAN_HH_
#define _MSCAN_HH_

#include <map>
#include <sstream>
#include <iomanip>

#include "addr2line.hh"
#include "bininfo.hh"

using namespace::std;

#define MAX_CPUS 8

typedef uint64_t call_tag_t;
typedef uint64_t pc_t;
typedef uint64_t timestamp_t;
typedef uint64_t object_id_t;
typedef uint64_t guest_addr_t;
typedef uint64_t tid_t;

class JsonDict;

class EntryHandler {
public:
    virtual void handle(const union mtrace_entry* entry) {}
    virtual void exit(void) {}
    virtual void exit(JsonDict* json_file) {}
private:
};

struct MtraceSummary {
    uint64_t app_ops;
    char app_name[32];
    uint16_t num_cpus;
    uint64_t num_ram;
};

struct MtraceObject {
    MtraceObject(void) {}

    MtraceObject(object_id_t id, const struct mtrace_label_entry* l) {
        id_ = id;
        guest_addr_ = l->guest_addr;
        bytes_= l->bytes;
        guest_addr_end_ = guest_addr_ + bytes_;
        name_ = l->str;
        alloc_pc_ = l->pc;
    }

    string name_;
    object_id_t id_;
    guest_addr_t guest_addr_;
    guest_addr_t guest_addr_end_;
    uint64_t bytes_;
    pc_t alloc_pc_;
};

class MtraceLabelMap {
public:
    void add_label(const struct mtrace_label_entry* l) {
        extern uint64_t mtrace_object_count;
        MtraceObject* o;
        object_id_t id;

        if (l->label_type == 0 || l->label_type >= mtrace_label_end)
            die("MtraceLabelMap::add_label: bad type: %u", l->label_type);

        if (object_first_.find(l->guest_addr) != object_first_.end()) {
	    fprintf(stderr, "add_label: l1 %s l2 %s\n", l->str, object_first_.find(l->guest_addr)->second->name_.c_str());
            die("MtraceLabelMap::add_label: overlapping labels");
	}

        id = ++mtrace_object_count;
        o = new MtraceObject(id, l);

        if (l->bytes == 0)
            die("MtraceLabelMap::add_label: 0 bytes");

        object_first_.insert(pair<guest_addr_t, MtraceObject*>(l->guest_addr, o));
        object_last_.insert(pair<guest_addr_t, MtraceObject*>(l->guest_addr + l->bytes - 1, o));
    }

    void rem_label(const struct mtrace_label_entry* l) {
        static uint64_t misses[mtrace_label_end];

        auto it = object_first_.find(l->guest_addr);
        if (it == object_first_.end()) {
            extern struct mtrace_host_entry mtrace_enable;

            if (mtrace_enable.access.mode)
                die("unknown label removed at guest addr %llx",
                    (unsigned long long)l->guest_addr);

            // We tolerate a few kfree calls for which we haven't
            // seen a previous kmalloc, because we might have missed
            // the kmalloc before the mtrace kernel code registered
            // the trace functions.
            misses[l->label_type]++;
            if (misses[l->label_type] > 200)
                die("suspicious number of misses %u",
                    l->label_type);
        } else {
            MtraceObject* o = it->second;

            object_last_.erase(o->guest_addr_ + o->bytes_ - 1);
            delete it->second;
            object_first_.erase(it);
        }
    }


    bool last_lower_bound(guest_addr_t addr, MtraceObject& ret) const {
        auto it = object_last_.lower_bound(addr);
        if (it == object_last_.end())
            return false;

        ret = *it->second;
        return true;
    }

    bool object(guest_addr_t addr, MtraceObject& ret) const {
        MtraceObject o;

        if (last_lower_bound(addr, o)) {
            if (o.guest_addr_ <= addr && addr < (o.guest_addr_ + o.bytes_)) {
                ret = o;
                return true;
            }
        }
        return false;
    }

    list<MtraceObject> objects_on_cline(guest_addr_t addr) const {
        list<MtraceObject> ret;
        guest_addr_t caddr;
        guest_addr_t next_caddr;

        caddr = addr & ~63;
        next_caddr = caddr + 64;

        auto it = object_last_.lower_bound(caddr);
        for (; it != object_last_.end(); ++it) {
            if (it->second->guest_addr_ < next_caddr &&
                caddr < it->second->guest_addr_end_) {
                ret.push_back(*(it->second));
                continue;
            }
            break;
        }

        return ret;
    }

private:
    map<guest_addr_t, MtraceObject*> object_first_;
    map<guest_addr_t, MtraceObject*> object_last_;
};

class MtraceAddr2label {
public:
    void add_label(const struct mtrace_label_entry* l) {
        if (l->label_type == mtrace_label_block)
            blocks_.add_label(l);
        else
            types_.add_label(l);
    }

    void rem_label(const struct mtrace_label_entry* l) {
        if (l->label_type == mtrace_label_block)
            blocks_.rem_label(l);
        else
            types_.rem_label(l);
    }


    bool last_lower_bound(guest_addr_t addr, MtraceObject& ret) const {
        return types_.last_lower_bound(addr, ret);
    }

    bool object(guest_addr_t addr, MtraceObject& ret) const {
        bool r;
        r = types_.object(addr, ret);
        if (!r)
            r = blocks_.object(addr, ret);
        return r;
    }

    list<MtraceObject> objects_on_cline(guest_addr_t addr) const {
        return types_.objects_on_cline(addr);
    }

private:
    MtraceLabelMap blocks_;
    MtraceLabelMap types_;
};

class MtraceAddr2line {
public:
    MtraceAddr2line(const char* elf_file)
        : addr2line_(elf_file) {}

    string function_name(pc_t pc) const {
        string func;
        string file;
        string line;

        all_string(pc, func, file, line);
        return func;
    }

    string function_description(pc_t pc) const {
        stringstream ss;
        string func;
        string file;
        string line;

        ss << std::setw(16) << std::setfill('0') << std::hex;
        ss << pc;
        
        all_string(pc, func, file, line);
        return "0x" + ss.str() + ":" + file + ":" + line + ":" + func;
    }

private:
    void all_string(pc_t pc, string& func, string& file, string& line) const {
        char* xfunc;
        char* xfile;
        int xline;

        if (pc == 0) {
            func = "(unknown function)";
            file = "(unknown file)";
            line = "0";
        } else if (addr2line_.lookup(pc, &xfunc, &xfile, &xline) == 0) {
            stringstream ss;

            func = xfunc;
            file = xfile;
            ss << xline;
            line = ss.str();

            free(xfunc);
            free(xfile);

        } else {
            stringstream ss;

            ss << pc;
            func = ss.str();
            file = "(unknown file)";
            line = "0";
        }
    }


    Addr2line addr2line_;
};

//
// A bunch of global state the default handlers update
//

// The first mtrace_host_entry
extern struct mtrace_host_entry mtrace_first;
// The current mtrace_host_entry
extern struct mtrace_host_entry mtrace_enable;
// An addr2line instance for the ELF file
extern MtraceAddr2line* addr2line;
// A summary of the application/workload
extern MtraceSummary mtrace_summary;
// The current fcall/kernel entry point
extern pc_t mtrace_call_pc[MAX_CPUS];
// The current task ID
extern tid_t mtrace_tid[MAX_CPUS];
// A map from guest address to kernel object
extern MtraceAddr2label mtrace_label_map;
// The current call stack
class CallTrace;
extern CallTrace* mtrace_call_trace;
// An object representing the DWARF in the kernel ELF
extern dwarf::dwarf mtrace_dwarf;

//
// Some helpers
//

static inline bool guest_enabled_mtrace(void)
{
    return mtrace_enable.access.mode != mtrace_record_disable;
}

static inline uint64_t total_instructions(void)
{
    if (!mtrace_first.access.mode || guest_enabled_mtrace())
        die("total_instructions: still processing log?");
    return mtrace_enable.global_ts - mtrace_first.global_ts;
}

#endif // _MSCAN_HH_
