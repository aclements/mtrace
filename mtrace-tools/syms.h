#include <map>

using namespace std;

struct Symbol {
	Symbol(void) {
		start_ = 0;
		bytes_ = 0;
		name_ = NULL;
	}

	Symbol(unsigned long start, unsigned long bytes, const char *name) {
		start_ = start;
		bytes_ = bytes;
		name_ = name;
	}

	unsigned long start_;
	unsigned long bytes_;
	const char    *name_;
};

class Syms {
public:
	Syms(void) {}

	void insert_sym(unsigned long start, unsigned long bytes, 
			const char *name) 
	{
		const char *dup = strdup(name);
		
		syms_[start] = Symbol(start, bytes, dup);
	}

	const char *lookup_name(unsigned long addr) {
		map<unsigned long, Symbol>::iterator it = syms_.find(addr);
		if (it == syms_.end())
			return NULL;

		return it->second.name_;
	}

private:
	map<unsigned long, Symbol> syms_;
};
