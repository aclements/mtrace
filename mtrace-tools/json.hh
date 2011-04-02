#ifndef _JSON_HH_
#define _JSON_HH_

#include <string>
#include <ext/hash_map>
#include <list>

using namespace::std;
using namespace::__gnu_cxx;

class JsonList;

typedef enum { json_string, json_u64, json_list } value_type_t;

class JsonObject {
public:
	virtual string str(void) const = 0;
};

class JsonString : public JsonObject {
public:
	JsonString(string value) : value_(value) {}

	virtual string str(void) const { 
		return string("\"") + value_ + string("\"");
	}
private:
	string value_;
};

class JsonUint : public JsonObject {
public:
	JsonUint(uint64_t value) : value_(value) {}

	virtual string str(void) const {
		char buf[64];
		snprintf(buf, sizeof(buf), "%lu", value_);
		return string(buf);
	}
private:
	uint64_t value_;
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

	void put(string key, string value) {
		put(key, new JsonString(value));
	}

	void put(string key, uint64_t value) {
		put(key, new JsonUint(value));
	}

	void put(string key, JsonObject *value) {
		table_[strdup(key.c_str())] = value;
	}

	virtual string str(void) const {
		if (!table_.size())
			return "{ }";

		string ret = "{";
		auto it = table_.begin();
		
		ret += string("\"") + string(it->first) + string("\"") + 
			string(": ") + it->second->str();
		++it;
		for (; it != table_.end(); ++it)
			ret += ", " + string("\"") + string(it->first) + string("\"") + 
				string(": ") + it->second->str();

		return ret + "}";
	}

private:
	hash_map<char *, JsonObject *> table_;
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

	void append(JsonObject *value) {
		list_.push_back(value);
	}

	virtual string str(void) const {
		if (!list_.size())
			return "[ ]";

		string ret = "[";		
		auto it = list_.begin();
		
		ret += (*it)->str();
		++it;
		for (; it != list_.end(); ++it)
			ret += ", " + (*it)->str();
		return ret + "]";
	}

private:
	list<JsonObject *> list_;
};

#endif
