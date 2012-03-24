#include <map>
#include <vector>
#include <set>
#include <stack>

#include "percallstack.hh"

using namespace std;

class AbstractSharing : public EntryHandler {
public:
    AbstractSharing(bool ascopes, bool unexpected)
        : ascopes_(ascopes), unexpected_(unexpected) { }

    virtual void handle(const union mtrace_entry* entry) {
        if (entry->h.type == mtrace_entry_fcall) {
            // This needs to happen whether we're active or not
            callstacks_.handle(&entry->fcall, this);
            return;
        }

        if (!guest_enabled_mtrace())
            return;
        if (mtrace_enable.access.mode != mtrace_record_ascope)
            die("Abstract sharing analysis requires mtrace_record_ascope mode");

        int cpu = entry->h.cpu;

        if (entry->h.type == mtrace_entry_ascope) {
            callstacks_.current(cpu)->handle(&entry->ascope);
        } else if (entry->h.type == mtrace_entry_avar) {
            callstacks_.current(cpu)->handle(&entry->avar);
        } else if (entry->h.type == mtrace_entry_access) {
            if (callstacks_.current(cpu))
                callstacks_.current(cpu)->handle(&entry->access);
        }
    }

    virtual void exit(JsonDict *json_file) {
        callstacks_.flush();

        if (ascopes_) {
            // Raw abstract and concrete sets
            JsonList *lst = JsonList::create();
            for (auto &ascope : scopes_) {
                JsonDict *od = JsonDict::create();
                od->put("name", ascope.name_);
                od->put("aread", JsonList::create(ascope.aread_.begin(), ascope.aread_.end()));
                od->put("awrite", JsonList::create(ascope.awrite_.begin(), ascope.awrite_.end()));

                JsonList *rw;
                rw = JsonList::create();
                for (auto &it : ascope.read_)
                    if (it.second.size())
                        rw->append(it.second);
                    else
                        rw->append(it.first);
                od->put("read", rw);
                rw = JsonList::create();
                for (auto &it : ascope.write_)
                    if (it.second.size())
                        rw->append(it.second);
                    else
                        rw->append(it.first);
                od->put("write", rw);

                lst->append(od);
            }
            json_file->put("abstract-scopes", lst);
        }

        if (unexpected_) {
            // Processed sets
            // XXX Would be nice to order these by the amount of sharing
            // XXX Produce a summary of sharing so its more obvious
            // when you screw up
            JsonList *lst = JsonList::create();
            for (auto &s1 : scopes_) {
                for (auto &s2 : scopes_) {
                    if (&s1 == &s2)
                        continue;
                    // If the two scopes ran on the same CPU, we'll
                    // get lots of "sharing" on per-CPU data, so don't
                    // compare scopes from the same CPU
                    if (s1.cpu_ == s2.cpu_)
                        continue;

                    bool abstract_sharing =
                        shares(s1.aread_.begin(),  s1.aread_.end(),
                               s1.awrite_.begin(), s1.awrite_.end(),

                               s2.aread_.begin(),  s2.aread_.end(),
                               s2.awrite_.begin(), s2.awrite_.end());
                    bool concrete_sharing =
                        shares(s1.read_.begin(),  s1.read_.end(),
                               s1.write_.begin(), s1.write_.end(),

                               s2.read_.begin(),  s2.read_.end(),
                               s2.write_.begin(), s2.write_.end());

                    if (concrete_sharing && !abstract_sharing) {
                        JsonDict *od = JsonDict::create();
                        od->put("s1", s1.name_);
                        od->put("s2", s2.name_);
                        JsonList *shared = JsonList::create();
                        shared_to_json(shared,
                                       s1.read_.begin(),  s1.read_.end(),
                                       s2.write_.begin(), s2.write_.end());
                        shared_to_json(shared,
                                       s1.write_.begin(), s1.write_.end(),
                                       s2.read_.begin(),  s2.read_.end());
                        shared_to_json(shared,
                                       s1.write_.begin(), s1.write_.end(),
                                       s2.write_.begin(), s2.write_.end());
                        od->put("shared", shared);
                        lst->append(od);
                    } else if (abstract_sharing && !concrete_sharing) {
                        fprintf(stderr, "Warning: Abstract sharing without concrete sharing: %s and %s\n",
                                s1.name_.c_str(), s2.name_.c_str());
                    }
                }
            }
            json_file->put("unexpected-sharing", lst);
        }
    }

    class Ascope {
    public:
        Ascope(string name, int cpu)
            : name_(name), cpu_(cpu) { }

        string name_;
        int cpu_;
        set<string> aread_;
        set<string> awrite_;
        map<uint64_t, string> read_;
        map<uint64_t, string> write_;
    };

private:
    bool ascopes_, unexpected_;

    class CallStack
    {
        AbstractSharing *a_;
        stack<Ascope> stack_;

        void pop()
        {
                // XXX Lots of copying
                Ascope *cur = &stack_.top();
                if (!cur->aread_.empty() || !cur->awrite_.empty())
                    a_->scopes_.push_back(*cur);
                stack_.pop();
        }

    public:
        CallStack(const mtrace_fcall_entry *fcall, AbstractSharing *a)
            : a_(a) {}
        ~CallStack()
        {
            while (!stack_.empty())
                pop();
        }

        void handle(const mtrace_ascope_entry *ascope)
        {
            if (ascope->exit)
                pop();
            else
                stack_.push(Ascope(ascope->name, ascope->h.cpu));
        }

        void handle(const mtrace_avar_entry *avar)
        {
            if (stack_.empty())
                die("avar without ascope");

            Ascope *cur = &stack_.top();
            string var = avar->name;
            if (avar->write) {
                cur->awrite_.insert(var);
                cur->aread_.erase(var);
            } else {
                if (!cur->awrite_.count(var))
                    cur->aread_.insert(var);
            }
        }

        void handle(const mtrace_access_entry *access)
        {
            if (stack_.empty())
                return;

            Ascope *cur = &stack_.top();
            // Since QEMU limits the granularity of tracking to 16
            // bytes in ascope mode, we need to do that, too.
            auto addr = access->guest_addr & ~15;
            // XXX Memory accesses apply to all abstract scopes on the stack
            MtraceObject obj;
            string name;
            if (mtrace_label_map.object(addr, obj)) {
                ostringstream ss;
                ss << obj.name_ << "+0x" << hex << (addr - obj.guest_addr_);
                name = ss.str();
            }
            switch (access->access_type) {
            case mtrace_access_st:
            case mtrace_access_iw:
                cur->write_[addr] = name;
                cur->read_.erase(addr);
                break;
            case mtrace_access_ld:
                if (!cur->write_.count(addr))
                    cur->read_[addr] = name;
                break;
            default:
                die("AbstractSharing::CallStack::handle: unknown access type");
            }
        }
    };

    PerCallStack<CallStack> callstacks_;

    vector<Ascope> scopes_;

    template<class InputIterator1, class InputIterator2>
    static bool shares(InputIterator1 r1begin, InputIterator1 r1end,
                       InputIterator1 w1begin, InputIterator1 w1end,
                       InputIterator2 r2begin, InputIterator2 r2end,
                       InputIterator2 w2begin, InputIterator2 w2end)
    {
        return
            intersects(r1begin, r1end, w2begin, w2end) ||
            intersects(w1begin, w1end, r2begin, r2end) ||
            intersects(w1begin, w1end, w2begin, w2end);
    }

    template<class InputIterator1, class InputIterator2>
    static bool intersects(InputIterator1 first1, InputIterator1 last1,
                           InputIterator2 first2, InputIterator2 last2)
    {
        while (first1 != last1 && first2 != last2) {
            if (*first1 < *first2)
                ++first1;
            else if (*first2 < *first1)
                ++first2;
            else
                return true;
        }
        return false;
    }

    template<class InputIterator1, class InputIterator2>
    static void shared_to_json(JsonList *shared,
                               InputIterator1 first1, InputIterator1 last1,
                               InputIterator2 first2, InputIterator2 last2)
    {
        while (first1 != last1 && first2 != last2) {
            if (*first1 < *first2)
                ++first1;
            else if (*first2 < *first1)
                ++first2;
            else {
                JsonDict *jd = JsonDict::create();
                char buf[64];
                sprintf(buf, "%lx", first1->first);
                jd->put("addr", buf);
                jd->put("name", first1->second);
                shared->append(jd);
                first1++;
                first2++;
            }
        }
    }
};
