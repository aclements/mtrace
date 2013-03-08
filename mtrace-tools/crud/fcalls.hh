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

    void handle(const struct mtrace_freturn_entry* e)
    {
        switch(e->type) {
        case mtrace_return_value:
            return_.push_back(*e);
            break;
        case mtrace_return_path_dep:
            return_path_dep_.push_back(*e);
            break;
        default:
            die("FCall::handle default");
        }
    }

    void handle(const struct mtrace_path_entry* e)
    {
        switch(e->type) {
        case mtrace_path_dep_read:
            path_dep_.push_back(*e);
            break;
        case mtrace_path_dep_write:
            write_path_dep_.push_back(pair<mtrace_path_entry, list<mtrace_path_entry> >(*e, path_dep_));
            break;
        default:
            die("FCall::handle default");
        }
    }

    JsonList* jsonPath(list<mtrace_path_entry>& l)
    {
        JsonList* r = JsonList::create();
        for (mtrace_path_entry& e : l) {
            JsonDict* d = JsonDict::create();
            d->put("path-dep-address", new JsonHex(e.guest_addr));
            d->put("path-dep-bytes", new JsonHex(e.bytes));
            r->append(d);
        }
        return r;
    }

    JsonDict* json_dict()
    {
        JsonDict* d = JsonDict::create();
        d->put("fcall-tag", e_.tag);
        d->put("fcall-pc", new JsonHex(e_.pc));
        d->put("fcall-description", addr2line->function_name(e_.pc));
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
            d2->put("access-type", a.access_type == mtrace_access_ld ? "l" : "s");
#if 0
            JsonList* path_deps = JsonList::create();
            for (mtrace_path_entry& p : path_dep_) {
                JsonDict* path = JsonDict::create();
                path->put("path-dep-address", new JsonHex(p.guest_addr));
                path->put("path-dep-bytes", new JsonHex(p.bytes));
                path_deps->append(path);
            }
            d2->put("path-deps", path_deps);
#endif
            l->append(d2);
        }
        d->put("fcall-access", l);

        l = JsonList::create();
        for (auto pear : write_path_dep_) {
            JsonDict* write_path = JsonDict::create();
            JsonList* path_deps = jsonPath(pear.second);
            
            write_path->put("write-address", new JsonHex(pear.first.guest_addr));
            write_path->put("write-bytes", pear.first.bytes);
            write_path->put("write-path-deps", path_deps);
            l->append(write_path);
        }
        d->put("fcall-writes", l);

        l = JsonList::create();        
        for (mtrace_freturn_entry& r2 : return_path_dep_) {
            JsonDict* d3 = JsonDict::create();
            d3->put("path-dep-address", new JsonHex(r2.guest_addr));
            d3->put("path-dep-bytes", new JsonHex(r2.bytes));
            l->append(d3);
        }
        d->put("fcall-return-deps", l);
        

#if 0
        l = JsonList::create();
        for (mtrace_freturn_entry& r : return_) {
            JsonDict* d2 = JsonDict::create();
            d2->put("return-address", new JsonHex(r.guest_addr));
            d2->put("return-bytes", new JsonHex(r.bytes));

            JsonList* l2 = JsonList::create();
            for (mtrace_freturn_entry& r2 : return_path_dep_) {
                JsonDict* d3 = JsonDict::create();
                d3->put("path-dep-address", new JsonHex(r2.guest_addr));
                d3->put("path-dep-bytes", new JsonHex(r2.bytes));
                l2->append(d3);
            }
            d2->put("return-path-deps", l2);
            l->append(d2);
        }
        d->put("fcall-return", l);
#endif

        return d;
    }
    
private:
    mtrace_fcall_entry         e_;
    list<mtrace_access_entry>  access_;
    list<mtrace_freturn_entry> return_;
    list<mtrace_freturn_entry> return_path_dep_;

    list<mtrace_path_entry>    path_dep_;
    list<pair<mtrace_path_entry, list<mtrace_path_entry> > > write_path_dep_;
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
        else if (entry->h.type == mtrace_entry_freturn)
            handle(&entry->freturn);
        else if (entry->h.type == mtrace_entry_path)
            handle(&entry->path);
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

    void handle(const struct mtrace_freturn_entry* e)
    {
        FCall* f = current_fcall_[e->h.cpu];

        if (f != nullptr)
            f->handle(e);
    }

    void handle(const struct mtrace_path_entry* e)
    {
        FCall* f = current_fcall_[e->h.cpu];

        if (f != nullptr)
            f->handle(e);
    }

    FCall*                             current_fcall_[MAX_CPUS];
    unordered_map<call_tag_t, FCall*>  fcall_;
};
