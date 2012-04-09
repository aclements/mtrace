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

//
// LockManager
//
bool
LockManager::release(const struct mtrace_lock_entry* lock, SerialSection& ss)
{
    static int misses;
    LockState* ls;
    
    auto it = state_.find(lock->lock);
    if (it == state_.end()) {
        misses++;
        if (misses >= 20)
            die("LockManager: released too many unheld locks");
        return false;
    }
    
    ls = it->second;
    ls->release(lock);
    
    if (ls->depth_ == 0) {
        ss = ls->ss_;
        stack_.remove(ls);
        state_.erase(it);
        delete ls;
        return true;
    }
    return false;
}

void
LockManager::acquire(const struct mtrace_lock_entry* lock)
{
    auto it = state_.find(lock->lock);
    
    if (it == state_.end()) {
        pair<LockStateTable::iterator, bool> r;
        LockState* ls = new LockState();
        r = state_.insert(pair<uint64_t, LockState*>(lock->lock, ls));
        if (!r.second)
            die("acquire: insert failed");
        stack_.push_front(ls);
        it = r.first;
    }
    it->second->acquire(lock);
}

void
LockManager::acquired(const struct mtrace_lock_entry* lock)
{
    static int misses;
    
    auto it = state_.find(lock->lock);
    
    if (it == state_.end()) {
        misses++;
        if (misses >= 10)
            die("acquired: acquired too many missing locks");
        return;
    }
    it->second->acquired(lock);
}

bool
LockManager::access(const struct mtrace_access_entry* a, SerialSection& ss)
{
    if (stack_.empty()) {
        ss.start = a->h.ts;
        ss.end = ss.start + 1;
        ss.acquire_cpu = a->h.cpu;
        ss.release_cpu = a->h.cpu;
        ss.call_pc = mtrace_call_pc[a->h.cpu];
        ss.acquire_pc = a->pc;
        if (a->traffic)
            ss.per_pc_coherence_miss[a->pc] = 1;
        else if (a->lock)
            ss.locked_inst = 1;
        return true;
    }
    
    stack_.front()->access(a);
    return false;
}

//
// SerialSections
//

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

//
// SerialSections::SerialSectionSummary
//
SerialSections::SerialSectionSummary::SerialSectionSummary(void)
    : per_pc_coherence_miss(),
      ts_cycles( {0}),
      acquires(0),
      mismatches(0),
      locked_inst(0)
{
}

void
SerialSections::SerialSectionSummary::add(const SerialSection* ss)
{
    if (ss->acquire_cpu != ss->release_cpu) {
        mismatches++;
        return;
    }
    
    if (ss->end < ss->start)
        die("SerialSectionSummary::add %"PRIu64" < %"PRIu64,
            ss->end, ss->start);
    
    ts_cycles[ss->acquire_cpu] += ss->end - ss->start;
    auto it = ss->per_pc_coherence_miss.begin();
    for (; it != ss->per_pc_coherence_miss.end(); ++it)
        per_pc_coherence_miss[it->first] += it->second;
    
    locked_inst += ss->locked_inst;
    acquires++;
}

timestamp_t
SerialSections::SerialSectionSummary::total_cycles(void) const
{
    timestamp_t sum = 0;
    int i;
    
    for (i = 0; i < MAX_CPUS; i++)
        sum += ts_cycles[i];
    return sum;
}

uint64_t
SerialSections::SerialSectionSummary::coherence_misses(void) const
{
    uint64_t sum = 0;
    
    auto it = per_pc_coherence_miss.begin();
    for (; it != per_pc_coherence_miss.end(); ++it)
        sum += it->second;
    
    return sum;
}
