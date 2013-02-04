class SBW0 : public EntryHandler
{
public:
    virtual void handle(const union mtrace_entry* e);
    virtual void exit(JsonDict *json_file);

private:
    void handle(const struct mtrace_access_entry* e);
    void handle(const struct mtrace_fcall_entry* e);


    list<JsonDict*> jaccess_;
    list<JsonDict*> jfcall_;

    unordered_map<call_tag_t, struct mtrace_fcall_entry>  fcall_;
    call_tag_t current_fcall_[MAX_CPUS];
};
