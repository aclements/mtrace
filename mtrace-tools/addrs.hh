#include <vector>

using namespace::std;
using namespace::__gnu_cxx;

struct ObjectAddrKey {
    guest_addr_t addr;
    object_id_t obj_id;
};

struct ObjectAddrEq {
    bool operator()(const ObjectAddrKey s1,
                    const ObjectAddrKey s2) const
    {
        return (s1.addr == s2.addr) && (s1.obj_id == s2.obj_id);
    }
};

struct ObjectAddrHash {
    size_t operator()(const ObjectAddrKey s) const {
        static const uint64_t length = sizeof(s)/sizeof(uintptr_t);
        register uintptr_t* k = (uintptr_t*)&s;
        static_assert(length == 2, "Bad length");
        
        return bb_hash(k, length);
    }
};

struct ObjectAddrStat {
    void init(const MtraceObject* object, const struct mtrace_access_entry* a);
    void add(const struct mtrace_access_entry* a);
    JsonDict* to_json(void);

    string name;
    guest_addr_t base;
    guest_addr_t address;
    vector<uint64_t> per_cpu;
    map<pc_t, uint64_t> per_pc;
};

class SharedAddresses : public EntryHandler {
public:
    virtual void handle(const union mtrace_entry* entry);
    virtual void exit(JsonDict* json_file);

private:

    hash_map<ObjectAddrKey, ObjectAddrStat, ObjectAddrHash, ObjectAddrEq> stat_;
};
