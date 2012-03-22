#include <map>
#include <set>
#include <string>

#include "addr2line.hh"
#include "json.hh"

using namespace::std;

//
// Distinct cache lines per system call
//
class DistinctSyscalls : public EntryHandler {
public:
    virtual void handle(const union mtrace_entry* entry) {
        int cpu;

        if (!guest_enabled_mtrace())
            return;

        cpu = entry->h.cpu;

        if (entry->h.type == mtrace_entry_access) {
            const struct mtrace_access_entry* a = &entry->access;
            if (a->traffic)
                tid_to_distinct_set_[current_[cpu]].insert(a->guest_addr & ~63UL);
        } else if (entry->h.type == mtrace_entry_fcall) {
            const struct mtrace_fcall_entry* f = &entry->fcall;

            switch (f->state) {
            case mtrace_resume:
                current_[cpu] = f->tid;
                break;
            case mtrace_start:
                current_[cpu] = f->tid;
                tid_to_pc_[current_[cpu]] = f->pc;
                break;
            case mtrace_pause:
                current_[cpu] = 0;
                break;
            case mtrace_done:
                count_tid(current_[cpu]);
                current_[cpu] = 0;
                break;
            default:
                die("DistinctSyscalls::handle: default error");
            }
        }
        return;
    }

    virtual void exit(void) {
        while (tid_to_distinct_set_.size())
            count_tid(tid_to_distinct_set_.begin()->first);

        printf("%-32s %10s %10s %10s\n",
               "function", "calls", "distinct", "ave");

        auto pit = pc_to_stats_.begin();
        for (; pit != pc_to_stats_.end(); ++pit) {
            uint64_t pc;
            string func;
            float n;

            pc = pit->first;
            n = (float)pit->second.distinct /
                (float)pit->second.calls;

            func = addr2line->function_name(pc);
            printf("%-32s %10"PRIu64" %10"PRIu64" %10.2f\n",
                   func.c_str(),
                   pit->second.calls,
                   pit->second.distinct, n);
        }
    }

    virtual void exit(JsonDict* json_file) {
        JsonList* list = JsonList::create();

        while (tid_to_distinct_set_.size())
            count_tid(tid_to_distinct_set_.begin()->first);

        auto pit = pc_to_stats_.begin();
        for (; pit != pc_to_stats_.end(); ++pit) {
            JsonDict* dict = JsonDict::create();
            uint64_t pc;
            string func;
            float n;

            pc = pit->first;
            n = (float)pit->second.distinct /
                (float)pit->second.calls;

            func = addr2line->function_name(pc);
            dict->put("entry", func);

            dict->put("calls", pit->second.calls);
            dict->put("distinct", pit->second.distinct);
            dict->put("ave", n);
            list->append(dict);
        }
        json_file->put("distinct-per-entry", list);
    }

    int64_t distinct(const char* syscall) {
        auto pit = pc_to_stats_.begin();
        for (; pit != pc_to_stats_.end(); ++pit) {
            uint64_t pc;
            string func;

            pc = pit->first;
            func = addr2line->function_name(pc);
            if (strcmp(syscall, func.c_str()) == 0)
                return pit->second.distinct;
        }
        return -1;
    }

private:
    void count_tid(uint64_t tid) {
        uint64_t pc;
        uint64_t n;

        n = tid_to_distinct_set_[tid].size();
        tid_to_distinct_set_.erase(tid);
        pc = tid_to_pc_[tid];
        tid_to_pc_.erase(tid);

        if (pc_to_stats_.find(pc) == pc_to_stats_.end()) {
            pc_to_stats_[pc].distinct = 0;
            pc_to_stats_[pc].calls = 0;
        }
        pc_to_stats_[pc].distinct += n;
        pc_to_stats_[pc].calls++;
    }

    struct SysStats {
        uint64_t distinct;
        uint64_t calls;
    };

    map<uint64_t, uint64_t> tid_to_pc_;
    map<uint64_t, SysStats> pc_to_stats_;
    map<uint64_t, set<uint64_t> > tid_to_distinct_set_;

    // The current tid
    uint64_t current_[MAX_CPUS];
};

//
// Distinct cache lines per application operation
//
class DistinctOps : public EntryHandler {
public:
    DistinctOps(DistinctSyscalls* ds) : ds_(ds) {
        appname_to_syscalls_["procy"] = {
            "stub_clone",
            "sys_exit_group",
            "sys_wait4"
        };
        appname_to_syscalls_["xv6-forktest"] = {
            "sys_fork",
            "sys_exit",
            "sys_wait"
        };
        appname_to_syscalls_["xv6-forktree"] = {
            "sys_fork",
            "sys_exit",
            "sys_wait"
        };
        appname_to_syscalls_["xv6-mapbench"] = {
            "sys_fork",
            "sys_exit",
            "sys_map",
            "sys_unmap",
            "sys_wait"
        };
        appname_to_syscalls_["xv6-dirbench"] = {
            "sys_open",
            "sys_close",
        };
    }

    virtual void exit(void) {
        uint64_t dist = distinct();
        float ave = (float)dist / (float)mtrace_summary.app_ops;

        printf("%s ops: %"PRIu64" distincts: %"PRIu64" ave: %.2f\n",
               mtrace_summary.app_name, mtrace_summary.app_ops, dist, ave);
    }

    virtual void exit(JsonDict* json_file) {
        uint64_t dist = distinct();
        float ave;

        if (mtrace_summary.app_ops)
            ave = (float)dist / (float)mtrace_summary.app_ops;
        else
            ave = 0.0;

        JsonDict* dict = JsonDict::create();
        dict->put("ops", mtrace_summary.app_ops);
        dict->put("distinct", dist);
        dict->put("ave", ave);
        json_file->put("distinct-per-op", dict);
    }

private:
    uint64_t distinct(void) {
        map<string, set<const char*> >::iterator it =
            appname_to_syscalls_.find(mtrace_summary.app_name);
        if (it == appname_to_syscalls_.end())
            die("DistinctOps::exit unable to find '%s'",
                mtrace_summary.app_name);

        set<const char*> *syscall = &it->second;
        set<const char*>::iterator sysit = syscall->begin();
        uint64_t n = 0;
        for (; sysit != syscall->end(); ++sysit) {
            int64_t r = ds_->distinct(*sysit);
            if (r < 0)
                die("DistinctOps::exit: unable to find %s", *sysit);
            n += r;
        }

        return n;
    }

    DistinctSyscalls* ds_;
    map<string, set<const char*> > appname_to_syscalls_;

};
