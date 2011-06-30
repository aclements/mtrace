//
// The data required to predict speedup using Eyerman's extension
// to Amdahl's law.  Also include coherence misses.
//
class Eyerman : public EntryHandler {
public:
    Eyerman(SerialSections* sersecs)
        : sersecs_(sersecs) {}

    virtual void exit(JsonDict* json_file) {
        timestamp_t total;
        timestamp_t critical;
        uint64_t coherence_misses;
        JsonDict* dict;

        if (mtrace_first.h.cpu != mtrace_enable.h.cpu)
            die("Eyerman::exit: CPU mismatch");

        //
        // XXX compute sequential execution as one cores execution time
        // the number of cores.  Better would be the sum of all cores
        // execution times.
        //
        total = mtrace_enable.h.ts - mtrace_first.h.ts;
        total *= mtrace_summary.num_cpus;
        
        //
        // The number of cycles spent in a critical/serial section. A coherence
        // miss is reported as a critical section of length 1 cycle.  No other
        // delays (e.g. miss penalty) are modeled.
        //
        critical = sersecs_->total_cycles();
        
        //
        // The number of coherence misses.
        //
        coherence_misses = sersecs_->coherence_misses();
        
        dict = JsonDict::create();
        dict->put("total", total);
        dict->put("critical", critical);
        dict->put("coherence-misses", coherence_misses);
        json_file->put("eyerman", dict);        
    }

private:
    SerialSections* sersecs_;
};
