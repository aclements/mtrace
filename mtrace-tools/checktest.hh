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

std::string scope_prefix("syscall:");

struct AccessSet {
    std::map<uint64_t, PhysicalAccess> read_;
    std::map<uint64_t, PhysicalAccess> write_;

    void add_access(const PhysicalAccess& pa, mtrace_access_t acctype) {
        for (uint64_t off = 0; off < pa.size; off++) {
            uint64_t addr = pa.access + off;

            switch (acctype) {
            case mtrace_access_st:
            case mtrace_access_iw:
                if (write_.count(addr) == 0)
                    write_[addr] = pa;
                read_.erase(addr);
                break;

            case mtrace_access_ld:
                if (write_.count(addr) == 0 && read_.count(addr) == 0)
                    read_[addr] = pa;
                break;

            default:
                assert(0);
            }
        }
    }
};

class Testcase : public EntryHandler {
public:
    Testcase(const std::string &n) : name_(n), scopecount_(0) {}

    virtual void handle(const union mtrace_entry* entry) {
        if (entry->h.type == mtrace_entry_ascope) {
            if (0 != scope_prefix.compare(0, scope_prefix.size(),
                                          entry->ascope.name,
                                          0, scope_prefix.size()))
                return;

            if (entry->ascope.exit)
                scopecount_--;
            else
                scopecount_++;

            assert(scopecount_ >= 0);
        }

        if (entry->h.type == mtrace_entry_access) {
            if (scopecount_ == 0)
                return;

            PhysicalAccess pa;
            pa.access = entry->access.guest_addr;
            pa.pc = entry->access.pc;
            pa.size = entry->access.bytes;
            pa.stack = 0;

            MtraceObject obj;
            if (mtrace_label_map.object(pa.access, obj)) {
                pa.type = obj.name_;
                pa.base = obj.guest_addr_;
            } else {
                pa.base = 0;
            }

            int cpu = entry->h.cpu;
            if (cpuacc_.count(cpu) == 0)
                cpuacc_[cpu] = AccessSet();

            cpuacc_[cpu].add_access(pa, entry->access.access_type);
        }
    }

    virtual void exit(JsonDict* out) {
        std::set<uint64_t> overlap_addrs;
        std::set<std::pair<PhysicalAccess, PhysicalAccess>> overlaps;

        for (auto& cpu_a: cpuacc_) {
            for (auto& cpu_b: cpuacc_) {
                if (cpu_b.first <= cpu_a.first)
                    continue;

                AccessSet& acc_a = cpu_a.second;
                AccessSet& acc_b = cpu_b.second;

                for (auto& write_a: acc_a.write_) {
                    uint64_t addr_a = write_a.first;
                    const PhysicalAccess& pa_a = write_a.second;

                    if (acc_b.read_.count(addr_a) && !overlap_addrs.count(pa_a.access)) {
                        overlaps.insert(make_pair(pa_a, acc_b.read_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                    if (acc_b.write_.count(addr_a) && !overlap_addrs.count(pa_a.access)) {
                        overlaps.insert(make_pair(pa_a, acc_b.write_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                }

                for (auto& read_a: acc_a.read_) {
                    uint64_t addr_a = read_a.first;
                    const PhysicalAccess& pa_a = read_a.second;

                    if (acc_b.write_.count(addr_a) && !overlap_addrs.count(pa_a.access)) {
                        overlaps.insert(make_pair(pa_a, acc_b.write_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                }
            }
        }

        out->put("name", name_);
        out->put("nshared", overlaps.size());
        JsonList* jshared = JsonList::create();
        for (auto& x: overlaps) {
            // jshared->append(x.first.to_json(&x.second));
            jshared->append(x.first.access);
        }
        out->put("shared", jshared);
    }

private:
    std::string name_;
    int scopecount_;
    std::map<int, AccessSet> cpuacc_;
};

class CheckTestcases : public EntryHandler {
public:
    CheckTestcases() : testcase_(0), testcases_() {}

    virtual void handle(const union mtrace_entry* entry) {

        switch (entry->h.type) {
        case mtrace_entry_host:
            if (entry->host.host_type == mtrace_access_all_cpu) {
                if (entry->host.access.mode == mtrace_record_ascope) {
                    testcase_ = new Testcase(entry->host.access.str);
                    testcases_.push_back(testcase_);
                }

                if (entry->host.access.mode == mtrace_record_disable) {
                    testcase_ = 0;
                }
            }
            break;

        case mtrace_entry_ascope:
        case mtrace_entry_access:
            if (testcase_)
                testcase_->handle(entry);
            break;

        default:
            break;
        }
    }

    virtual void exit(JsonDict *json_file) {
        JsonList* jl = JsonList::create();
        json_file->put("testcases", jl, false);

        for (auto& t: testcases_) {
            JsonDict* jd = JsonDict::create();
            jl->append(jd, false);
            t->exit(jd);
            jd->done();
        }

        jl->done();
    }

private:
    Testcase* testcase_;
    list<Testcase*> testcases_;
};
