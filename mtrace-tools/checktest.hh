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
#include "generator.hh"
#include <dwarf++.hh>

std::string scope_prefix("syscall:");

struct AccessSet
{
    typedef std::map<uint64_t, PhysicalAccess> addr_map_t;
    addr_map_t addrs_;

    void add(PhysicalAccess &&pa)
    {
        if (pa.size == 0)
            return;

        // Test for overlap
        auto oit = addrs_.lower_bound(pa.end());
        // oit points to the access that starts *after* pa ends
        if (oit == addrs_.begin() || !(--oit)->second.overlaps(pa)) {
            // No overlap
            oit = addrs_.insert(make_pair(pa.access, std::move(pa))).first;
            try_merge(oit);
            if (oit != addrs_.begin())
                try_merge(--oit);
            return;
        }

        if (oit->second.access == pa.access && oit->second.size == pa.size &&
            oit->second.is_write == pa.is_write)
            // Trivial overlap.  Keep earlier access.
            return;

        // Complex overlap.  We have to handle the following cases
        //
        // |--pa--|           |--pa--|   |-----pa------|     |pa|
        //    |overlap|   |overlap|         |overlap|     |overlap|
        //  r1     r2      r3      r4     r1         r4    r3    r2
        //
        // pa may overlap with additional existing regions.  We'll
        // handle that when we recursively insert the new regions.
        auto overlap = oit->second;
        addrs_.erase(oit);

        // r1 and r3
        add(trim(pa, pa.access, overlap.access));
        add(trim(overlap, overlap.access, pa.access));

        // r2 and r4
        add(trim(overlap, pa.end(), overlap.end()));
        add(trim(pa, overlap.end(), pa.end()));

        // Overlapping area.  Here we have to choose which wins.
        // Prefer the earlier access unless we're changing a read to a
        // write.
        add(trim((pa.is_write && !overlap.is_write) ? pa : overlap,
                 std::max(pa.access, overlap.access),
                 std::min(pa.end(), overlap.end())));
    }

    generator<std::pair<PhysicalAccess, PhysicalAccess>>
        conflicts(const AccessSet &o)
    {
        auto it1 = addrs_.begin(), end1 = addrs_.end();
        auto it2 = o.addrs_.begin(), end2 = o.addrs_.end();

        return make_generator([=]() mutable {
                while (it1 != end1 && it2 != end2) {
                    const PhysicalAccess &acc1 = it1->second,
                        &acc2 = it2->second;
                    if (acc1.end() > acc2.end())
                        ++it2;
                    else
                        ++it1;
                    if (acc1.conflicts(acc2))
                        return make_pair(acc1, acc2);
                }
                throw generator_stop();
            });
    }

private:
    // Try to merge *(it+1) into *it.
    void try_merge(addr_map_t::iterator it)
    {
        auto next = it;
        if (++next == addrs_.end())
            return;
        if (it->second.try_merge(next->second))
            // it->second always has the lower address, so we don't
            // have to adjust keys.
            addrs_.erase(next);
    }

    PhysicalAccess trim(PhysicalAccess pa, uint64_t base, uint64_t end)
    {
        pa.access = base;
        pa.size = base < end ? end - base : 0;
        return pa;
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

        /* Skip sharing of user-space data by uaccess() in multiple procs */
        if (entry->guest_addr < 0x800000000000)
            return;

        PhysicalAccess pa;
        pa.access = entry->guest_addr;
        pa.pc = entry->pc;
        pa.size = entry->bytes;
        pa.stack = mtrace_call_trace->get_current(cpu);
        pa.is_write = (entry->access_type != mtrace_access_ld);

        MtraceObject obj;
        if (mtrace_label_map.object(pa.access, obj)) {
            pa.type = obj.name_;
            pa.base = obj.guest_addr_;
        } else {
            pa.base = 0;
        }

        cpuacc_[cpu].add(std::move(pa));
    }

    void done() {
        if (done_)
            return;
        done_ = true;

        for (auto& cpu_a: cpuacc_) {
            for (auto& cpu_b: cpuacc_) {
                if (cpu_b.first <= cpu_a.first)
                    continue;

                AccessSet& acc_a = cpu_a.second;
                AccessSet& acc_b = cpu_b.second;

                for (auto &conflict : acc_a.conflicts(acc_b))
                    overlaps_.insert(conflict);
            }
        }

        scopecount_.clear();
        cpuacc_.clear();
    }

    bool exit(JsonDict* out) {
        done();
        if (overlaps_.size() == 0) {
            // return false;
        }

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
