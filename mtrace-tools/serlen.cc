#include <stdint.h>
#include <string.h>
#include <assert.h>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}
#include "mscan.hh"
#include "json.hh"
#include "serlen.hh"

static JsonDict*
jsonify(const struct mtrace_lock_entry& start, 
        const struct mtrace_lock_entry& done)
{
    JsonDict* d = JsonDict::create();
    d->put("pc", new JsonHex(start.pc));
    d->put("lock", new JsonHex(start.lock));
    d->put("start", start.h.ts);
    d->put("stop", done.h.ts);
    d->put("total", done.h.ts - start.h.ts);
    return d;
}

void
SerLen::exit(JsonDict *json_file)
{
    JsonList* l;

    l = JsonList::create();
    for (auto section : jsection_)
        l->append(section);
    json_file->put("sections", l);
}

void
SerLen::handle(const union mtrace_entry* entry)
{
    switch(entry->h.type) {
    case mtrace_entry_lock:
        return handle(&entry->lock);
    default:
        die("%s: default", __func__);
    }
}

void
SerLen::handle(const struct mtrace_lock_entry* e)
{
    switch (e->op) {
    case mtrace_lockop_acquired: {
        auto it = lock_.find(e->lock);
        if (it != lock_.end())
            die("double mtrace_lockop_acquired");
        lock_[e->lock] = *e;
        break;
    }
    case mtrace_lockop_release: {
        auto it = lock_.find(e->lock);
        if (it == lock_.end())
            die("mtrace_lockop_release");
        JsonDict* d = jsonify(it->second, *e);
        jsection_.push_back(d);
        lock_.erase(it);
        break;
    }
    case mtrace_lockop_acquire:
        // Do nothing..
        break;
    default:
        die("%s: default", __func__);
    }
}
