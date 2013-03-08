class SerLen : public EntryHandler
{
    typedef uint64_t lock_id_t;

public:
    virtual void handle(const union mtrace_entry* e);
    virtual void exit(JsonDict *json_file);

private:
    void handle(const struct mtrace_lock_entry* e);    

    unordered_map<lock_id_t, struct mtrace_lock_entry> lock_;
    list<JsonDict*> jsection_;
};
