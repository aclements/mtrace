#include <unordered_map>
#include <list>

class CrimeStack
{
    struct Summary
    {
        Summary(call_tag_t tag, pc_t pc, string description,
                const CallStack* stack)
            : tag_(tag), pc_(pc), description_(description), stack_(stack)
        {
        }

        void to_json(JsonDict* dict)
        {
            JsonList* stack;
            if (stack_)
                stack = stack_->new_json();
            else
                stack = JsonList::create();
            dict->put("stack", stack);
            dict->put("fcall-tag", tag_);
            dict->put("pc", new JsonHex(pc_));
            dict->put("description", description_);
        }

        call_tag_t tag_;
        pc_t pc_;
        string description_;
        const CallStack* stack_;
    };

public:
    CrimeStack(const struct mtrace_access_entry* e,
               const CallStack* stack)
        : stack_(stack) 
    {
        pc_ = e->pc;
        description_ = addr2line->function_description(pc_);
    }

    void blame(call_tag_t tag, pc_t pc, string description,
               const CallStack* stack)
    {
        victim_.push_back(Summary(tag, pc, description, stack));
    }

    size_t victim_count()
    {
        return victim_.size();
    }

    void to_json(JsonDict* dict)
    {
        dict->put("pc", new JsonHex(pc_));
        dict->put("description", description_);

        JsonList* stack;
        if (stack_)
            stack = stack_->new_json();
        else
            stack = JsonList::create();
        dict->put("stack", stack);

        JsonList* victims = JsonList::create();
        for (auto v : victim_) {
            JsonDict* vdict = JsonDict::create();
            v.to_json(vdict);
            victims->append(vdict);
        }
        dict->put("victims", victims);
    }

private:
    pc_t             pc_;
    string           description_;
    const CallStack* stack_;
    list<Summary>    victim_;
};

class PerpCall
{
public:
    PerpCall(const struct mtrace_fcall_entry* e)
      : count_(0) 
    {
        tag_ = e->tag;
        pc_ = e->pc;
        description_ = addr2line->function_description(pc_);
    }

    void to_json(JsonDict* dict)
    {
        dict->put("fcall-tag", tag_);
        dict->put("victim-count", count_);
        dict->put("pc", new JsonHex(pc_));
        dict->put("description", description_);

        JsonList* list = JsonList::create();
        for (auto cs : crime_) {
            if (cs->victim_count()) {
                JsonDict* crimeDict = JsonDict::create();
                cs->to_json(crimeDict);
                list->append(crimeDict);
            }
        }
        dict->put("crimes", list);
    }

    void handle(const struct mtrace_access_entry* e)
    {
        const CallStack* stack = mtrace_call_trace->get_current(e->h.cpu);
        CrimeStack* crime = new CrimeStack(e, stack);

        crime_.push_back(crime);
        last_location_[e->guest_addr] = crime;
    }

    void blame(const struct mtrace_access_entry* e,
               const PerpCall* victim)
    {
        auto it = last_location_.find(e->guest_addr);
        if (it == last_location_.end())
            die("PerpCall: blame: couldn't find %lx\n", e->guest_addr);
        it->second->blame(victim->tag_, victim->pc_, victim->description_,
                          mtrace_call_trace->get_current(e->h.cpu));
        count_++;
    }

private:
    call_tag_t tag_;
    pc_t       pc_;
    string     description_;
    uint64_t   count_;
    unordered_map<guest_addr_t, CrimeStack*> last_location_;
    list<CrimeStack*> crime_;
};

class BlameCalls : public EntryHandler
{
    typedef uint64_t addr_t;
    typedef uint64_t pc_t;

public:
    BlameCalls()
    {
        for (int i = 0; i < MAX_CPUS; i++)
            current_perp_[i] = nullptr;
    }

    virtual void handle(const union mtrace_entry* entry)
    {
        if (entry->h.type == mtrace_entry_access)
            handle(&entry->access);
        else if (entry->h.type == mtrace_entry_fcall)
            handle(&entry->fcall);
    }

    virtual void exit(JsonDict *json_file)
    {
        JsonList* list = JsonList::create();
        for (auto p : perp_) {
            PerpCall* perp = p.second;
            JsonDict* dict = JsonDict::create();
            perp->to_json(dict);
            list->append(dict);
        }
        json_file->put("blame-calls", list);
    }

private:
    void handle(const struct mtrace_access_entry* entry)
    {
        PerpCall* perp;
        auto it = last_update_.find(entry->guest_addr);
        if (it != last_update_.end()) {
            PerpCall* victim = current_perp_[entry->h.cpu];
            if (victim == nullptr)
                die("BlameCalls: handle: no victim");
            perp = it->second;
            perp->blame(entry, victim);
            last_update_.erase(it);
        }
        
        perp = current_perp_[entry->h.cpu];
        if (perp != nullptr) {
            perp->handle(entry);
            last_update_[entry->guest_addr] = perp;
        }
    }

    void handle(const struct mtrace_fcall_entry* e)
    {
        switch(e->state) {
        case mtrace_resume: {
            assert(current_perp_[e->h.cpu] == nullptr);
            auto it = perp_.find(e->tag);
            assert(it != perp_.end());
            current_perp_[e->h.cpu] = it->second;
            break;
        }
        case mtrace_start: {
            assert(current_perp_[e->h.cpu] == nullptr);
            PerpCall* p = new PerpCall(e);
            perp_[e->tag] = p;
            current_perp_[e->h.cpu] = p;
            break;
        }
        case mtrace_pause:
        case mtrace_done:
            current_perp_[e->h.cpu] = nullptr;
            break;
        default:
            die("BlameCalls: mtrace_fcall_entry default");
        }
    }

    unordered_map<addr_t, PerpCall*>      last_update_;
    unordered_map<call_tag_t, PerpCall*>  perp_;
    PerpCall*                             current_perp_[MAX_CPUS];
};
