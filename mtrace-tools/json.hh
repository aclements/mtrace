#ifndef _JSON_HH_
#define _JSON_HH_

// JSON spec: http://www.json.org/

#include <string>
#include <unordered_map>
#include <list>
#include <stdexcept>

using namespace::std;

static string
tab(int level)
{
    string s = "";
    for (int i = 0; i < level; i++)
        s = s + "  ";
    return s;
}

class JsonObject {
public:
    virtual string str(int level) const = 0;
};

static JsonObject *jsonify(JsonObject *value) {
    return value;
}

class JsonString : public JsonObject {
public:
    virtual string str(int level) const {
        return string("\"") + value_ + string("\"");
    }
private:
    JsonString(string value) : value_(value) {}
    string value_;

    friend JsonObject *jsonify(string value);
};

JsonObject *jsonify(string value) {
    return new JsonString(value);
}

class JsonUint : public JsonObject {
public:
    virtual string str(int level) const {
        char buf[64];
        snprintf(buf, sizeof(buf), "%lu", value_);
        return string(buf);
    }
private:
    JsonUint(uint64_t value) : value_(value) {}
    uint64_t value_;

    friend JsonObject *jsonify(uint64_t value);
};

JsonObject *jsonify(uint64_t value) {
    return new JsonUint(value);
}

static JsonObject *jsonify(uint8_t value) {
    return jsonify((uint64_t)value);
}

class JsonInt : public JsonObject {
public:
    virtual string str(int level) const {
        char buf[64];
        snprintf(buf, sizeof(buf), "%ld", value_);
        return string(buf);
    }
private:
    JsonInt(int64_t value) : value_(value) {}
    int64_t value_;

    friend JsonObject *jsonify(int value);
};

JsonObject *jsonify(int value) {
    return new JsonInt(value);
}

class JsonHex : public JsonObject {
public:
    JsonHex(uint64_t value) : value_(value) {}

    virtual string str(int level) const {
        char buf[64];
        // JSON spec doesn't include hex numbers
        snprintf(buf, sizeof(buf), "\"0x%lx\"", value_);
        return string(buf);
    }
private:
    uint64_t value_;
};

class JsonFloat : public JsonObject {
public:
    virtual string str(int level) const {
        char buf[64];
        snprintf(buf, sizeof(buf), "%f", value_);
        return string(buf);
    }
private:
    JsonFloat(float value) : value_(value) {}
    float value_;

    friend JsonObject *jsonify(float value);
};

JsonObject *jsonify(float value) {
    return new JsonFloat(value);
}

class JsonDict : public JsonObject {
public:
    ~JsonDict(void) {
        for (auto it : table_)
            delete it.second;
    }

    static JsonDict* create() {
        return new JsonDict();
    }

    static JsonDict* create(ostream *out, int level = 0) {
        return new JsonDict(out, level);
    }

    void end() {
        if (out_) {
            if (first_)
                (*out_) << "{ }";
            else
                (*out_) << '\n' << tab(level_) << '}';
            out_->flush();
            delete this;
        }
    }

    template<typename T>
    void put(string key, T value) {
        JsonObject *o = jsonify(value);

        if (out_) {
            key_out(key);
            val_out(o);
            out_->flush();
            delete o;
            return;
        }

        auto keyit = keys_.find(key);
        if (keyit != keys_.end()) {
            if (out_)
                throw std::runtime_error("JsonDict already contains key " + key);
            table_.erase(keyit->second);
            keys_.erase(keyit);
        }

        auto it = table_.insert(table_.end(), make_pair(key, o));
        keys_[key] = it;
    }

    template<typename T>
    T *start(string key) {
        if (out_) {
            key_out(key);
            return T::create(out_, level_ + 1);
        } else {
            T* obj = T::create();
            put(key, obj);
            return obj;
        }
    }

    virtual string str(int level) const {
        if (out_)
            throw std::runtime_error("Cannot str a streaming JsonDict");

        if (!table_.size())
            return "{ }";

        ostringstream stream;
        out_ = &stream;
        first_ = true;
        level_ = level;

        for (auto &it : table_) {
            key_out(it.first);
            val_out(it.second);
        }
        (*out_) << '\n' << tab(level) << '}';
        out_ = nullptr;

        return stream.str();
    }

private:
    typedef list<pair<string, JsonObject*> > table_type;
    table_type table_;
    unordered_map<string, table_type::iterator> keys_;

    // Streaming dictionaries
    mutable ostream *out_;
    mutable bool first_;
    mutable int level_;

    JsonDict(ostream *out = nullptr, int level = 0)
        : out_(out), first_(true), level_(level) { }
    JsonDict(const JsonDict&);
    JsonDict& operator=(const JsonDict&);

    void key_out(const string &key) const {
        if (first_)
            (*out_) << '{';
        else
            (*out_) << ',';
        (*out_) << '\n' << tab(level_+1) << '\"' << key << "\": ";
        first_ = false;
    }

    void val_out(JsonObject *o) const {
        (*out_) << o->str(level_+1);
    }
};

class JsonList : public JsonObject {
public:
    ~JsonList(void) {
        while (list_.size()) {
            auto it = list_.begin();
            JsonObject* o = *it;
            list_.erase(it);
            delete o;
        }
    }

    static JsonList* create() {
        return new JsonList();
    }

    static JsonList* create(ostream *out, int level = 0) {
        return new JsonList(out, level);
    }

    template<typename InputIterator>
    static JsonList* create(InputIterator first, InputIterator last) {
        JsonList *lst = create();
        for (InputIterator it = first; it != last; it++)
            lst->append(*it);
        return lst;
    }

    void end() {
        if (out_) {
            if (first_)
                (*out_) << "[ ]";
            else
                (*out_) << " ]";
            out_->flush();
            delete this;
        }
    }

    template<typename T>
    void append(T value) {
        JsonObject *o = jsonify(value);

        if (out_) {
            val_out(o);
            out_->flush();
            delete o;
        } else {
            list_.push_back(o);
        }
    }

    size_t size() {
        return list_.size();
    }

    virtual string str(int level) const {
        if (out_)
            throw std::runtime_error("Cannot str a streaming JsonList");

        if (!list_.size())
            return "[ ]";

        string ret = "[";
        auto it = list_.begin();

        ret += "\n" + tab(level+1) + (*it)->str(level+1);
        ++it;
        for (; it != list_.end(); ++it)
            ret += ",\n" + tab(level+1) + (*it)->str(level+1);
        return ret + " ]";
    }

private:
    list<JsonObject*> list_;

    // Streaming lists
    mutable ostream *out_;
    mutable bool first_;
    mutable int level_;

    JsonList(ostream *out = nullptr, int level = 0)
        : out_(out), first_(true), level_(level) { }
    JsonList(const JsonList&);
    JsonList& operator=(const JsonList&);

    void val_out(JsonObject *o) const {
        if (first_)
            (*out_) << '[';
        else
            (*out_) << ',';
        (*out_) << '\n' << tab(level_+1) << o->str(level_+1);
        first_ = false;
    }
};

#endif
