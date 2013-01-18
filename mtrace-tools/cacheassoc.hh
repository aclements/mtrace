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

struct CacheSet {
    CacheSet(uint64_t nways = 8) :
        nways_(nways), accesses_(), cached_(), misses_(0)
    {}

    void add_access(const PhysicalAccess& pa) {
        bool cached = false;
        for (uint64_t x: cached_)
            if (x / 64 == pa.access / 64)
                cached = true;

        if (!cached) {
            if (cached_.size() >= nways_)
                cached_.pop_front();
            cached_.push_back(pa.access);
            misses_++;
            accesses_.insert(pa);
        }
    }

    uint64_t nways_;
    std::set<PhysicalAccess> accesses_;
    std::list<uint64_t> cached_;
    uint64_t misses_;
};

class CacheSim {
public:
    CacheSim(uint64_t nsets = 512) :
        nsets_(nsets),
        set_(new CacheSet[nsets])
    {}

    void handle(const mtrace_access_entry* entry) {
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

        uint64_t set = (pa.access / 64) % nsets_;
        set_[set].add_access(pa);
    }

    void exit(JsonList* jl) {
        std::sort(&set_[0], &set_[nsets_],
                  [](const CacheSet& a, const CacheSet& b) {
                      return a.misses_ > b.misses_;
                  });
        for (uint i = 0; i < nsets_; i++) {
            CacheSet& cs = set_[i];
            JsonDict* jd = JsonDict::create();
            jd->put("misses", cs.misses_);
            JsonList* accesses = JsonList::create();
            for (const PhysicalAccess& pa: cs.accesses_)
                accesses->append(pa.to_json());
            jd->put("accesses", accesses);
            jl->append(jd);
        }
    }

private:
    const uint64_t nsets_;
    CacheSet* set_;
};

class CacheAssoc : public EntryHandler {
public:
    CacheAssoc() : active_(false), ncpu_(0) {}

    virtual void handle(const union mtrace_entry* entry) {
        switch (entry->h.type) {
        case mtrace_entry_machine:
            if (ncpu_)
                break;

            ncpu_ = entry->machine.num_cpus;
            sim_ = new CacheSim[ncpu_];
            break;

        case mtrace_entry_host:
            if (!ncpu_)
                break;

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
                sim_[entry->h.cpu].handle(&entry->access);
            break;

        default:
            break;
        }
    }

    virtual void exit(JsonDict *json_file) {
        if (!ncpu_)
            return;

        JsonDict* jd = JsonDict::create();
        json_file->put("cachesim_cpus", jd, false);

        for (int i = 0; i < ncpu_; i++) {
            char n[64];
            sprintf(n, "cpu%d", i);

            JsonList* cpulist = JsonList::create();
            jd->put(n, cpulist, false);
            sim_[i].exit(cpulist);
            cpulist->done();
        }
        jd->done();
    }

private:
    bool active_;
    int ncpu_;
    CacheSim* sim_;
};
