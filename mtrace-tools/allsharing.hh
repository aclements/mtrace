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

struct AccessSetCount {
    std::map<uint64_t, PhysicalAccess> read_;
    std::map<uint64_t, PhysicalAccess> write_;

    std::map<uint64_t, uint64_t> readcount_;
    std::map<uint64_t, uint64_t> writecount_;

    void add_access(const PhysicalAccess& pa, mtrace_access_t acctype) {
        // assume PhysicalAccess'es do not span cache lines
        uint64_t addr = pa.access / 64 * 64;  // cacheline

        switch (acctype) {
        case mtrace_access_st:
        case mtrace_access_iw:
            writecount_[addr]++;
            if (write_.count(addr) == 0)
                write_[addr] = pa;
            read_.erase(addr);
            break;

        case mtrace_access_ld:
            readcount_[addr]++;
            if (write_.count(addr) == 0 && read_.count(addr) == 0)
                read_[addr] = pa;
            break;

        default:
            assert(0);
        }
    }
};

class AllSharing : public EntryHandler {
public:
    AllSharing() : active_(false) {}

    virtual void handle(const union mtrace_entry* entry) {
        switch (entry->h.type) {
        case mtrace_entry_host:
            if (entry->host.host_type == mtrace_access_all_cpu) {
                if (entry->host.access.mode == mtrace_record_ascope) {
                    active_ = true;
                }

                if (entry->host.access.mode == mtrace_record_disable) {
                    active_ = false;
                }
            }
            break;

        case mtrace_entry_access:
            if (active_)
                handle(&entry->access);
            break;

        default:
            break;
        }
    }

    void handle(const mtrace_access_entry* entry) {
        int cpu = entry->h.cpu;

        PhysicalAccess pa;
        pa.access = entry->guest_addr;
        pa.pc = entry->pc;
        pa.size = entry->bytes;
        pa.stack = 0;

        MtraceObject obj;
        if (mtrace_label_map.object(pa.access, obj)) {
            pa.type = obj.name_;
            pa.base = obj.guest_addr_;
        } else {
            pa.base = 0;
        }

        if (cpuacc_.count(cpu) == 0)
            cpuacc_[cpu] = AccessSetCount();

        cpuacc_[cpu].add_access(pa, entry->access_type);
        allacc_.add_access(pa, entry->access_type);
    }

    virtual void exit(JsonDict *json_file) {
        JsonList* jl = JsonList::create();
        json_file->put("shared_cachelines", jl, false);

        std::set<uint64_t> overlap_addrs;
        std::set<std::pair<PhysicalAccess, PhysicalAccess>> overlaps;

        for (auto& write: allacc_.write_) {
            uint64_t addr = write.first;

            int cpu_count = 0;
            int maxcpu = 0;
            std::map<uint64_t, uint64_t> cpu_reads;
            std::map<uint64_t, uint64_t> cpu_writes;
            PhysicalAccess pa;
            for (auto& cpu: cpuacc_) {
                AccessSetCount& cpuacc = cpu.second;

                maxcpu = std::max(maxcpu, cpu.first);
                if (!cpuacc.read_.count(addr) && !cpuacc.write_.count(addr))
                    continue;
                cpu_count++;
                cpu_reads[cpu.first] += cpuacc.readcount_[addr];
                cpu_writes[cpu.first] += cpuacc.writecount_[addr];

                if (cpuacc.read_.count(addr))
                    pa = cpuacc.read_[addr];
                if (cpuacc.write_.count(addr))
                    pa = cpuacc.write_[addr];
            }

            if (cpu_count <= 1)
                continue;

            JsonDict* jd = JsonDict::create();
            jd->put("pa", pa.to_json());

            JsonList* cpureads = JsonList::create();
            JsonList* cpuwrites = JsonList::create();
            for (int i = 0; i <= maxcpu; i++) {
                cpureads->append(cpu_reads[i]);
                cpuwrites->append(cpu_writes[i]);
            }
            jd->put("cpureads", cpureads);
            jd->put("cpuwrites", cpuwrites);
            jl->append(jd);
        }

        jl->done();
    }

private:
    bool active_;
    std::map<int, AccessSetCount> cpuacc_;
    AccessSetCount allacc_;
};
