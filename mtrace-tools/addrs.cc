#include <stdio.h>
#include <string.h>

#include <ext/hash_map>
#include <assert.h>
#include <cinttypes>
#include <list>
#include <sstream>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}

#include "mscan.hh"

#include "hash.h"
#include "addrs.hh"
#include "json.hh"

#include "bininfo.hh"

//
// ObjectAddrStat
//
void
ObjectAddrStat::init(const MtraceObject* object,
                     const struct mtrace_access_entry* a)
{
    name = object->name_;
    base = object->guest_addr_;
    address = a->guest_addr;
    add(a);
}

void
ObjectAddrStat::add(const struct mtrace_access_entry* a)
{
    {
        auto it = per_pc.find(a->pc);
        if (it == per_pc.end())
            per_pc[a->pc] = 1;
        else
            it->second++;
    }
    if (per_cpu.size() < (unsigned)a->h.cpu+1)
        per_cpu.resize(a->h.cpu+1);
    per_cpu[a->h.cpu]++;
}

JsonDict*
ObjectAddrStat::to_json(void)
{
    JsonDict* d = JsonDict::create();

    d->put("name", name);
    //d->put("address", new JsonHex(address));
    d->put("address",
           resolve_type_offset(mtrace_dwarf, name, base, address-base));

    JsonList* l = JsonList::create();
    uint64_t tot = 0;
    for (auto it = per_pc.begin(); it != per_pc.end(); ++it) {
        JsonDict* count = JsonDict::create();
        //count->put("pc", new JsonHex(it->first));
        count->put("info", addr2line->function_description(it->first));
        count->put("count", it->second);
        l->append(count);
        tot += it->second;
    }
    JsonList* cpu_accesses = JsonList::create();
    unsigned i;
    for (i = 0; i < per_cpu.size(); i++)
        cpu_accesses->append(per_cpu[i]);
    for (; i < mtrace_summary.num_cpus; i++)
        cpu_accesses->append(0);

    d->put("count-per-pc", l);
    d->put("count-per-cpu", cpu_accesses);
    d->put("count", tot);

    return d;
}

//
// SharedAddresses
//
void
SharedAddresses::handle(const union mtrace_entry* entry)
{
    MtraceObject object;
    ObjectAddrKey key;

    if (entry->h.type != mtrace_entry_access)
        die("SharedAddresses::handle");

    const struct mtrace_access_entry* a = &entry->access;
    key.obj_id = 0;
    if (mtrace_label_map.object(a->guest_addr, object))
        key.obj_id = object.id_;
    key.addr = a->guest_addr;

    auto it = stat_.find(key);
    if (it == stat_.end())
        stat_[key].init(&object, a);
    else
        it->second.add(a);
}

void
SharedAddresses::exit(JsonDict* json_file)
{
    JsonList* list = JsonList::create();

    for (auto it = stat_.begin(); it != stat_.end(); ++it)
        list->append(it->second.to_json());

    json_file->put("shared-addresses", list);
}
