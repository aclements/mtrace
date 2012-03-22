#include <map>
#include <vector>

#include "json.hh"

using namespace::std;

//
// Every access per system call
//
class SyscallAccesses : public EntryHandler {
    friend class SyscallAccessesPC;
public:
    virtual void handle(const union mtrace_entry* entry) {
        struct mtrace_access_entry* cp;
        int cpu;

        if (!guest_enabled_mtrace())
            return;
        if (entry->h.type != mtrace_entry_access)
            return;

        cpu = entry->h.cpu;

        cp = (struct mtrace_access_entry*)malloc(sizeof(*cp));
        memcpy(cp, entry, sizeof(*cp));
        pc_to_stats_[mtrace_call_pc[cpu]].push_back(cp);
    }

    virtual void exit(JsonDict* json_file) {
        JsonDict* dict = JsonDict::create();

        auto it = pc_to_stats_.begin();
        for (; it != pc_to_stats_.end(); ++it) {
            JsonList* list;
            uint64_t pc;
            string name;

            list = JsonList::create();

            pc = it->first;
            name = addr2line->function_name(pc);

            auto vit = it->second.begin();
            for (; vit != it->second.end(); ++vit) {
                JsonDict* entry = JsonDict::create();
                entry->put("pc", new JsonHex((*vit)->pc));
                entry->put("guest_addr", new JsonHex((*vit)->guest_addr));
                entry->put("traffic", (*vit)->traffic);
                entry->put("lock", (*vit)->lock);
                entry->put("access_type", (*vit)->access_type == mtrace_access_ld ? "ld" : "st");
                list->append(entry);
            }

            dict->put(name, list);
        }

        json_file->put("syscall-accesses", dict);
    }

private:
    map<pc_t, vector<struct mtrace_access_entry*> > pc_to_stats_;
};

//
// The PC of every acesss per system call
//
class SyscallAccessesPC: public EntryHandler {
public:
    SyscallAccessesPC(SyscallAccesses* accesses)
        : accesses_(accesses) {}

    virtual void exit(JsonDict* json_file) {
        JsonDict* dict = JsonDict::create();
        auto stats = &accesses_->pc_to_stats_;

        auto it = stats->begin();
        for (; it != stats->end(); ++it) {
            JsonList* list;
            string name;
            uint64_t pc;

            list = JsonList::create();

            pc = it->first;
            name = addr2line->function_name(pc);

            map<pc_t, uint64_t> pc_to_count;

            auto vit = it->second.begin();
            for (; vit != it->second.end(); ++vit) {
                pc_t access_pc = (*vit)->pc;
                auto pit = pc_to_count.find(access_pc);
                if (pit == pc_to_count.end())
                    pc_to_count[access_pc] = 1;
                else
                    pit->second++;
            }

            auto mit = pc_to_count.begin();
            for (; mit != pc_to_count.end(); ++mit) {
                JsonDict* entry = JsonDict::create();
                entry->put("pc", new JsonHex(mit->first));
                entry->put("count", mit->second);
                list->append(entry);
            }

            dict->put(name, list);
        }

        json_file->put("syscall-accesses-pc", dict);
    }

private:
    SyscallAccesses* accesses_;
};
