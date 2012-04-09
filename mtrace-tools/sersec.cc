#include <stdio.h>
#include <string.h>

#include <ext/hash_map>
#include <assert.h>
#include <cinttypes>
#include <list>

extern "C" {
#include <mtrace-magic.h>
#include "util.h"
}

#include "mscan.hh"

#include "hash.h"
#include "sersec.hh"

SerialSections::SerialSections(void)
  : lock_manager_() 
{
}

void
SerialSections::handle(const union mtrace_entry* entry)
{
    if (!guest_enabled_mtrace())
        return;
    
    switch (entry->h.type) {
    case mtrace_entry_access:
        handle_access(&entry->access);
        break;
    case mtrace_entry_lock:
        handle_lock(&entry->lock);
        break;
    default:
        die("SerialSections::handle type %u", entry->h.type);
    }
}

void
SerialSections::exit(void)
{
    auto it = stat_.begin();
    
    printf("serial sections:\n");
    
    for (; it != stat_.end(); ++it) {
        SerialSectionStat* stat = &it->second;
        printf(" %s  %"PRIu64"  %"PRIu64"\n",
               stat->name.c_str(),
                   stat->summary.total_cycles(),
               stat->summary.acquires);
    }
}

void
SerialSections::exit(JsonDict* json_file)
{
    JsonList* list = JsonList::create();
    
    auto it = stat_.begin();
    for (; it != stat_.end(); ++it) {
        SerialSectionStat* stat = &it->second;
        JsonDict* dict = JsonDict::create();
        dict->put("name", stat->name);
        dict->put("section-type", stat->lock_section ? "lock" : "instruction");
        populateSummaryDict(dict, &stat->summary);
        
        JsonList* pc_list = JsonList::create();
        auto mit = stat->per_pc.begin();
        for (; mit != stat->per_pc.end(); ++mit) {
            JsonDict* pc_dict = JsonDict::create();
            SerialSectionSummary* sum = &mit->second;
            pc_t pc = mit->first;
            
            pc_dict->put("pc", new JsonHex(pc));
            pc_dict->put("info", addr2line->function_description(pc));
            populateSummaryDict(pc_dict, sum);
            
            pc_list->append(pc_dict);
        }
        dict->put("per-acquire-pc", pc_list);
        
        JsonList* tid_list = JsonList::create();
        auto tit = stat->per_tid.begin();
        for (; tit != stat->per_tid.end(); ++tit) {
            JsonDict* tid_dict = JsonDict::create();
            SerialSectionSummary* sum = &tit->second;
            tid_t tid = tit->first;
            
            tid_dict->put("tid", tid);
            tid_dict->put("acquires", sum->acquires);
            tid_list->append(tid_dict);
        }
        dict->put("tids", tid_list);
        
        list->append(dict);
    }
    json_file->put("serial-sections", list);
}

timestamp_t
SerialSections::total_cycles(void) const
{
    timestamp_t sum = 0;
    
    auto it = stat_.begin();
    for (; it != stat_.end(); ++it)
        sum += it->second.summary.total_cycles();
    return sum;
}

uint64_t
SerialSections::coherence_misses(void) const
{
    uint64_t sum = 0;
    
    auto it = stat_.begin();
    for (; it != stat_.end(); ++it)
        sum += it->second.summary.coherence_misses();
    return sum;
}

void
SerialSections::populateSummaryDict(JsonDict* dict, SerialSectionSummary* sum)
{
    timestamp_t tot;
    float bench_frac;
    JsonList* list;
    int i;
    
    tot = sum->total_cycles();
    dict->put("total-instructions",  tot);
    bench_frac = (float)tot / (float)total_instructions();
    dict->put("benchmark-fraction", bench_frac);
    list = JsonList::create();
    for (i = 0; i < mtrace_summary.num_cpus; i++) {
        float percent;
        
        percent = 0.0;
        if (tot != 0.0)
            percent = 100.0 * ((float)sum->ts_cycles[i] / (float)tot);
        list->append(percent);
    }
    dict->put("per-cpu-percent", list);
    dict->put("acquires", sum->acquires);
    
    JsonList* coherence_list = JsonList::create();
    auto it = sum->per_pc_coherence_miss.begin();
    for (; it != sum->per_pc_coherence_miss.end(); ++it) {
        JsonDict* coherence_dict = JsonDict::create();
        pc_t pc = it->first;
        coherence_dict->put("pc", new JsonHex(pc));
        coherence_dict->put("info", addr2line->function_description(pc));
        coherence_dict->put("count", it->second);
        coherence_list->append(coherence_dict);
    }
    dict->put("coherence-miss", sum->coherence_misses());
    dict->put("coherence-miss-list", coherence_list);
    
    dict->put("locked-inst", sum->locked_inst);
    dict->put("mismatches", sum->mismatches);
}

void
SerialSections::handle_lock(const struct mtrace_lock_entry* l)
{
    switch (l->op) {
    case mtrace_lockop_release: {
        SerialSection ss;
        if (lock_manager_.release(l, ss)) {
            MtraceObject object;
            SerialSectionKey key;
            
            if (!mtrace_label_map.object(l->lock, object)) {
                fprintf(stderr, "SerialSections::handle: missing %"PRIx64" (%s) %"PRIx64"\n",
                        l->lock, l->str, l->pc);
                return;
            }
            
            key.lock_id = l->lock;
            key.obj_id = object.id_;
            
            auto it = stat_.find(key);
            if (it == stat_.end()) {
                stat_[key].init(&object, l);
                it = stat_.find(key);
            }
            it->second.add(&ss);
        }
        break;
    }
    case mtrace_lockop_acquire:
        lock_manager_.acquire(l);
        break;
    case mtrace_lockop_acquired:
        lock_manager_.acquired(l);
        break;
    default:
        die("SerialSections::handle: bad op");
    }
}

void
SerialSections::handle_access(const struct mtrace_access_entry* a)
{
    SerialSection ss;
    
    if (lock_manager_.access(a, ss)) {
        MtraceObject object;
        SerialSectionKey key;
        
        key.obj_id = 0;
        if (mtrace_label_map.object(a->guest_addr, object))
            key.obj_id = object.id_;
        key.lock_id = a->guest_addr;
        
        auto it = stat_.find(key);
        if (it == stat_.end()) {
            stat_[key].init(&object, a, object.name_);
            it = stat_.find(key);
        }
        it->second.add(&ss);
    }
}
