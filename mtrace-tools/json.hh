#ifndef _JSON_HH_
#define _JSON_HH_

#include <string>
#include <ext/hash_map>
#include <list>

using namespace::std;
using namespace::__gnu_cxx;

class JsonList;

typedef enum { json_string, json_u64, json_list } value_type_t;

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

class JsonString : public JsonObject {
	friend class JsonDict;
	friend class JsonList;
public:
	virtual string str(int level) const { 
		return string("\"") + value_ + string("\"");
	}
private:
	JsonString(string value) : value_(value) {}
	string value_;
};

class JsonUint : public JsonObject {
	friend class JsonDict;
	friend class JsonList;
public:
	virtual string str(int level) const {
		char buf[64];
		snprintf(buf, sizeof(buf), "%lu", value_);
		return string(buf);
	}
private:
	JsonUint(uint64_t value) : value_(value) {}
	uint64_t value_;
};

class JsonHex : public JsonObject {
public:
	JsonHex(uint64_t value) : value_(value) {}

	virtual string str(int level) const {
		char buf[64];
		snprintf(buf, sizeof(buf), "%lx", value_);
		return string(buf);
	}
private:
	uint64_t value_;
};

class JsonFloat : public JsonObject {
	friend class JsonDict;
	friend class JsonList;
public:
	virtual string str(int level) const {
		char buf[64];
		snprintf(buf, sizeof(buf), "%f", value_);
		return string(buf);
	}
private:
	JsonFloat(float value) : value_(value) {}
	float value_;
};

class JsonDict : public JsonObject {
public:
	~JsonDict(void) {
		while (table_.size()) {
			auto it = table_.begin();
			char *s = it->first;
			JsonObject *o = it->second;
			table_.erase(it);
			free(s);
			delete o;
		}
	}

	static JsonDict *create() {
		return new JsonDict();
	}

	void put(string key, string value) {
		put(key, new JsonString(value));
	}

	void put(string key, uint64_t value) {
		put(key, new JsonUint(value));
	}

	void put(string key, uint8_t value) {
		put(key, new JsonUint((uint64_t)value));
	}

	void put(string key, float value) {
		put(key, new JsonFloat(value));
	}

	void put(string key, JsonObject *value) {
		table_[strdup(key.c_str())] = value;
	}

	virtual string str(int level) const {
		if (!table_.size())
			return "{ }";

		string ret = "{";
		auto it = table_.begin();
		
		ret += "\n" + tab(level+1) + string("\"") + string(it->first) + string("\"") + 
			string(": ") + it->second->str(level+1);
		++it;
		for (; it != table_.end(); ++it)
			ret += ",\n" + tab(level+1) + string("\"") + string(it->first) + string("\"") + 
				string(": ") + it->second->str(level+1);

		return ret + "\n" + tab(level) + "}";
	}

private:
	hash_map<char *, JsonObject *> table_;

	JsonDict() {}
	JsonDict(const JsonDict&);
	JsonDict& operator=(const JsonDict&);
};

class JsonList : public JsonObject {
public:
	~JsonList(void) {
		while (list_.size()) {
			auto it = list_.begin();
			JsonObject *o = *it;
			list_.erase(it);
			delete o;
		}
	}

	static JsonList *create() {
		return new JsonList();
	}

	void append(JsonObject *value) {
		list_.push_back(value);
	}

	virtual string str(int level) const {
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
	list<JsonObject *> list_;

	JsonList() {}
	JsonList(const JsonList&);
	JsonList& operator=(const JsonList&);
};

#endif
