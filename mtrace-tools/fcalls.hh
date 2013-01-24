static inline string
get_object_name(guest_addr_t addr)
{
    for (MtraceObject& o : mtrace_label_map.objects_on_cline(addr)) {
        if (o.guest_addr_ <= addr && addr < o.guest_addr_end_) {
            return o.name_;
        }
    }

    return "(unknown)";
}

class FCall
{
public:
    FCall(const struct mtrace_fcall_entry* e) : e_(*e)
    {
    }

    void handle(const struct mtrace_access_entry* e)
    {
        access_.push_back(*e);
    }

    JsonDict* json_dict()
    {
        JsonDict* d = JsonDict::create();
        d->put("fcall-tag", e_.tag);
        d->put("fcall-pc", new JsonHex(e_.pc));
        d->put("fcall-description", addr2line->function_description(e_.pc));
        d->put("fcall-tid", e_.tid);

        JsonList* l = JsonList::create();
        for (mtrace_access_entry &a : access_) {
            JsonDict* d2 = JsonDict::create();
            d2->put("access-count", a.h.access_count);
            d2->put("access-pc", new JsonHex(a.pc));
            d2->put("access-description",
                    addr2line->function_description(a.pc));
            d2->put("access-address", new JsonHex(a.guest_addr));
            d2->put("access-object", get_object_name(a.guest_addr));
            l->append(d2);
        }
        d->put("fcall-access", l);

        return d;
    }
    
private:
    mtrace_fcall_entry        e_;
    list<mtrace_access_entry> access_;
};

class FCalls : public EntryHandler
{
public:
    FCalls()
    {
        for (int i = 0; i < MAX_CPUS; i++)
            current_fcall_[i] = nullptr;
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
        JsonList* l = JsonList::create();
        for (auto p : fcall_) {
            FCall* fc = p.second;
            l->append(fc->json_dict());
        }
        json_file->put("fcalls", l);
    }

private:
    void handle(const struct mtrace_access_entry* e)
    {
        FCall* f = current_fcall_[e->h.cpu];

        if (f != nullptr)
            f->handle(e);
    }

    void handle(const struct mtrace_fcall_entry* e)
    {
        switch(e->state) {
        case mtrace_resume: {
            assert(current_fcall_[e->h.cpu] == nullptr);
            auto it = fcall_.find(e->tag);
            assert(it != fcall_.end());
            current_fcall_[e->h.cpu] = it->second;
            break;
        }
        case mtrace_start: {
            assert(current_fcall_[e->h.cpu] == nullptr);
            FCall* f = new FCall(e);
            fcall_[e->tag] = f;
            current_fcall_[e->h.cpu] = f;
            break;
        }
        case mtrace_pause:
        case mtrace_done:
            current_fcall_[e->h.cpu] = nullptr;
            break;
        default:
            die("FCalls: mtrace_fcall_entry default");
        }
    }

    FCall*                             current_fcall_[MAX_CPUS];
    unordered_map<call_tag_t, FCall*>  fcall_;
};
