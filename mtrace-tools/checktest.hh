#include <map>
#include <vector>
#include <set>
#include <stack>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <assert.h>

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

class Testcase {
public:
    Testcase(const std::string &n, bool kernelscope)
      : name_(n), kernelscope_(kernelscope), scopecount_(), done_(false) {}

    void handle(const mtrace_ascope_entry* entry) {
        int cpu = entry->h.cpu;

        if (0 != scope_prefix.compare(0, scope_prefix.size(),
                                      entry->name,
                                      0, scope_prefix.size()))
            return;

        if (scopecount_.count(cpu) == 0)
            scopecount_[cpu] = 0;

        if (entry->exit)
            scopecount_[cpu]--;
        else
            scopecount_[cpu]++;

        assert(scopecount_[cpu] >= 0);
    }

    void handle(const mtrace_access_entry* entry) {
        int cpu = entry->h.cpu;

        if (!kernelscope_ && scopecount_[cpu] == 0)
            return;

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

        if (cpuacc_.count(cpu) == 0)
            cpuacc_[cpu] = AccessSet();

        cpuacc_[cpu].add_access(pa, entry->access_type);
    }

    void done() {
        if (done_)
            return;
        done_ = true;

        std::set<uint64_t> overlap_addrs;

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
                        overlaps_.insert(make_pair(pa_a, acc_b.read_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                    if (acc_b.write_.count(addr_a) && !overlap_addrs.count(pa_a.access)) {
                        overlaps_.insert(make_pair(pa_a, acc_b.write_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                }

                for (auto& read_a: acc_a.read_) {
                    uint64_t addr_a = read_a.first;
                    const PhysicalAccess& pa_a = read_a.second;

                    if (acc_b.write_.count(addr_a) && !overlap_addrs.count(pa_a.access)) {
                        overlaps_.insert(make_pair(pa_a, acc_b.write_[addr_a]));
                        overlap_addrs.insert(pa_a.access);
                    }
                }
            }
        }

        scopecount_.clear();
        cpuacc_.clear();
    }

    bool exit(JsonDict* out) {
        done();
        if (overlaps_.size() == 0)
            return false;

        out->put("name", name_);
        JsonList* jshared = JsonList::create();
        for (auto& x: overlaps_)
            jshared->append(x.first.to_json(&x.second));
        out->put("shared", jshared);
        return true;
    }

private:
    std::string name_;
    bool kernelscope_;
    std::map<int, int> scopecount_;
    std::map<int, AccessSet> cpuacc_;

    bool done_;
    std::set<std::pair<PhysicalAccess, PhysicalAccess>> overlaps_;
};

class CheckTestcases : public EntryHandler {
public:
    CheckTestcases() : testcase_(0), testcases_() {}

    virtual void handle(const union mtrace_entry* entry) {
        switch (entry->h.type) {
        case mtrace_entry_host:
            if (entry->host.host_type == mtrace_access_all_cpu) {
                if (entry->host.access.mode == mtrace_record_ascope ||
                    entry->host.access.mode == mtrace_record_kernelscope)
                {
                    bool kscope = (entry->host.access.mode == mtrace_record_kernelscope);
                    testcase_ = new Testcase(entry->host.access.str, kscope);
                    testcases_.push_back(testcase_);
                }

                if (entry->host.access.mode == mtrace_record_disable) {
                    if (testcase_)
                        testcase_->done();
                    testcase_ = 0;
                }
            }
            break;

        case mtrace_entry_ascope:
            if (testcase_)
                testcase_->handle(&entry->ascope);
            break;

        case mtrace_entry_access:
            if (testcase_)
                testcase_->handle(&entry->access);
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
            if (t->exit(jd))
                jl->append(jd);
        }

        jl->done();
    }

private:
    Testcase* testcase_;
    list<Testcase*> testcases_;
};
