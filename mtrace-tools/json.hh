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
    virtual ~JsonObject() { }

    /**
     * Write this object to the given stream with the given
     * indentation.  If the object has been fully written, this should
     * return true to return the output token to the parent
     * immediately.  Otherwise, this should return false and, once it
     * is fully written, it should invoke parent->write_next(o, this)
     * to return the output token to the parent and indicate that this
     * child may be deleted.
     */
    virtual bool write_to(ostream *o, int level, JsonObject *parent) = 0;

    /**
     * For a collection, indicate that no more elements will be
     * added.  For other types, does nothing.
     */
    virtual void done() { }

private:
    friend class JsonDict;
    friend class JsonList;
    virtual void write_next(ostream *o, JsonObject *child) { }
};

static inline JsonObject *jsonify(JsonObject *value) {
    return value;
}
static inline JsonObject *jsonify(string value);
static inline JsonObject *jsonify(uint64_t value);
static inline JsonObject *jsonify(uint8_t value);
static inline JsonObject *jsonify(int value);
static inline JsonObject *jsonify(float value);

class JsonString : public JsonObject {
    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        *o << '"' << value_ << '"';
        return true;
    }

private:
    JsonString(string value) : value_(value) {}
    string value_;

    friend JsonObject *jsonify(string value);
};

static inline JsonObject *jsonify(string value) {
    return new JsonString(value);
}

class JsonUint : public JsonObject {
    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        *o << value_;
        return true;
    }

private:
    JsonUint(uint64_t value) : value_(value) {}
    uint64_t value_;

    friend JsonObject *jsonify(uint64_t value);
};

static inline JsonObject *jsonify(uint64_t value) {
    return new JsonUint(value);
}

static inline JsonObject *jsonify(uint8_t value) {
    return jsonify((uint64_t)value);
}

class JsonInt : public JsonObject {
public:
    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        *o << value_;
        return true;
    }

private:
    JsonInt(int64_t value) : value_(value) {}
    int64_t value_;

    friend JsonObject *jsonify(int value);
};

static inline JsonObject *jsonify(int value) {
    return new JsonInt(value);
}

class JsonHex : public JsonObject {
public:
    JsonHex(uint64_t value) : value_(value) {}

    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        char buf[64];
        // JSON spec doesn't include hex numbers
        snprintf(buf, sizeof(buf), "\"0x%lx\"", value_);
        *o << buf;
        return true;
    }

private:
    uint64_t value_;
};

class JsonFloat : public JsonObject {
public:
    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%f", value_);
        *o << buf;
        return true;
    }

private:
    JsonFloat(float value) : value_(value) {}
    float value_;

    friend JsonObject *jsonify(float value);
};

static inline JsonObject *jsonify(float value) {
    return new JsonFloat(value);
}

class JsonDict : public JsonObject {
public:
    ~JsonDict(void) {
        done();
        for (auto it : table_)
            delete it.second;
    }

    static JsonDict* create() {
        return new JsonDict();
    }

    void done() {
        if (!done_) {
            done_ = true;
            flush();
        }
    }

    template<typename T>
    void put(string key, T value, bool auto_done = true) {
        if (done_)
            throw std::runtime_error("cannot append to ended JsonDict");

        JsonObject *o = jsonify(value);
        table_.push_back(make_pair(key, o));
        if (auto_done)
            o->done();
        flush();
    }

    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        out_ = o;
        level_ = level;
        parent_ = nullptr;
        first_ = true;
        flush();
        if (done_ && out_) {
            out_ = nullptr;
            return true;
        }
        parent_ = parent;
        return false;
    }

protected:
    virtual void write_next(ostream *o, JsonObject *child) {
        delete child;
        out_ = o;
        flush();
    }

private:
    list<pair<string, JsonObject*> > table_;

    // Streaming dictionaries
    ostream *out_;
    int level_;
    JsonObject *parent_;
    bool first_;
    bool done_;

    JsonDict() : out_(nullptr), done_(false) { }
    JsonDict(const JsonDict&);
    JsonDict& operator=(const JsonDict&);

    void flush() {
        while (out_ && !table_.empty()) {
            auto obj = table_.front();
            table_.pop_front();

            if (first_)
                *out_ << '{';
            else
                *out_ << ',';
            first_ = false;
            *out_ << '\n' << tab(level_+1) << "\"" << obj.first << "\": ";

            if (obj.second->write_to(out_, level_+1, this)) {
                delete obj.second;
            } else {
                // obj owns the ostream now.  It'll pass it back to us
                // later by calling write_next.
                out_ = nullptr;
            }
        }

        if (done_ && out_) {
            if (first_)
                *out_ << "{ }";
            else
                *out_ << '\n' << tab(level_) << '}';
            if (parent_)
                parent_->write_next(out_, this);
        } else if (out_) {
            out_->flush();
        }
    }
};

class JsonList : public JsonObject {
public:
    ~JsonList(void) {
        done();
        for (auto it : list_)
            delete it;
    }

    static JsonList* create() {
        return new JsonList();
    }

    template<typename InputIterator>
    static JsonList* create(InputIterator first, InputIterator last) {
        JsonList *lst = create();
        for (InputIterator it = first; it != last; it++)
            lst->append(*it);
        return lst;
    }

    void done() {
        if (!done_) {
            done_ = true;
            flush();
        }
    }

    template<typename T>
    void append(T value, bool auto_done = true) {
        if (done_)
            throw std::runtime_error("cannot append to ended JsonList");

        JsonObject *o = jsonify(value);
        list_.push_back(o);
        if (auto_done)
            o->done();
        flush();
    }

    virtual bool write_to(ostream *o, int level, JsonObject *parent) {
        out_ = o;
        level_ = level;
        parent_ = nullptr;
        first_ = true;
        flush();
        if (done_ && out_) {
            out_ = nullptr;
            return true;
        }
        parent_ = parent;
        return false;
    }

protected:
    virtual void write_next(ostream *o, JsonObject *child) {
        delete child;
        out_ = o;
        flush();
    }

private:
    list<JsonObject*> list_;

    // Streaming lists
    ostream *out_;
    int level_;
    JsonObject *parent_;
    bool first_;
    bool done_;

    JsonList() : out_(nullptr), done_(false) { }
    JsonList(const JsonList&);
    JsonList& operator=(const JsonList&);

    void flush() {
        while (out_ && !list_.empty()) {
            JsonObject *obj = list_.front();
            list_.pop_front();

            if (first_)
                *out_ << '[';
            else
                *out_ << ',';
            first_ = false;
            *out_ << '\n' << tab(level_+1);

            if (obj->write_to(out_, level_+1, this)) {
                delete obj;
            } else {
                // obj owns the ostream now.  It'll pass it back to us
                // later by calling write_next.
                out_ = nullptr;
            }
        }

        if (done_ && out_) {
            if (first_)
                *out_ << "[ ]";
            else
                *out_ << " ]";
            if (parent_)
                parent_->write_next(out_, this);
        } else if (out_) {
            out_->flush();
        }
    }
};

#endif
