#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <list>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}

#include "addr2line.hh"
#include "mscan.hh"
#include "json.hh"
#include "sbw0.hh"

static JsonDict*
jsonify(const struct mtrace_access_entry& entry)
{
    static const string access_str[] = { "?", "l", "s", "s" };

    JsonDict* d = JsonDict::create();
    // mtrace_entry_header
    d->put("cpu", entry.h.cpu);
    d->put("access-count", entry.h.access_count);
    // mtrace_access_entry
    d->put("access-type", access_str[entry.access_type]);
    d->put("traffic", entry.traffic);
    d->put("pc", new JsonHex(entry.pc));
    d->put("host-addr", new JsonHex(entry.host_addr));
    d->put("guest-addr", new JsonHex(entry.guest_addr));
    d->put("bytes", entry.bytes);
    d->put("deps", entry.deps);
    d->put("description",
           addr2line->lookup(entry.pc).to_string());

    return d;
}

static JsonDict*
jsonify(const struct mtrace_fcall_entry& start, 
        const struct mtrace_fcall_entry& done)
{
    JsonDict* d = JsonDict::create();
    d->put("tag", start.tag);
    d->put("cpu", start.h.cpu);
    d->put("description",
           addr2line->lookup(start.pc).func);
    d->put("pc", new JsonHex(start.pc));
    d->put("start-access-count", start.h.access_count);
    d->put("done-access-count", done.h.access_count);
    d->put("done-value", done.state == mtrace_done_value);

    return d;
}

void
SBW0::exit(JsonDict *json_file)
{
    JsonList* l;

    l = JsonList::create();
    for (auto access : jaccess_)
        l->append(access);
    json_file->put("accesses", l);

    l = JsonList::create();
    for (auto fcall : jfcall_)
        l->append(fcall);
    json_file->put("fcalls", l);
}

void
SBW0::handle(const union mtrace_entry* entry)
{
    switch(entry->h.type) {
    case mtrace_entry_access:
        return handle(&entry->access);
    case mtrace_entry_fcall:
        return handle(&entry->fcall);
    default:
        die("%s: default", __func__);
    }
}

void
SBW0::handle(const struct mtrace_access_entry* e)
{
    JsonDict* d = jsonify(*e);
    d->put("fcall", current_fcall_[e->h.cpu]);
    jaccess_.push_back(d);
}

void
SBW0::handle(const struct mtrace_fcall_entry* e)
{
    switch(e->state) {
    case mtrace_resume: {
        assert(current_fcall_[e->h.cpu] == 0);
        auto it = fcall_.find(e->tag);
        assert(it != fcall_.end());
        current_fcall_[e->h.cpu] = e->tag;
        break;
    }
    case mtrace_start: {
        assert(current_fcall_[e->h.cpu] == 0);
        fcall_[e->tag] = *e;
        current_fcall_[e->h.cpu] = e->tag;
        break;
    }
    case mtrace_pause:
        current_fcall_[e->h.cpu] = 0;
        break;
    case mtrace_done_value: {
    case mtrace_done:
        call_tag_t t = current_fcall_[e->h.cpu];
        assert(t != 0);
        current_fcall_[e->h.cpu] = 0;
        JsonDict* d = jsonify(fcall_[t], *e);
        jfcall_.push_back(d);
        break;
    }
    default:
        die("%s: default", __func__);
    }
}
