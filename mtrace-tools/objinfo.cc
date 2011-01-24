// -*- c-file-style: "linux"; indent-tabs-mode: t -*-

#include "objinfo.h"

#include <map>
#include <string>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dwarf.h>
#include <libdwarf.h>

using namespace std;

typedef int DID;
typedef map<DID, struct oi_die*> DieMap;
typedef map<string, DID> NameMap;
typedef map<unsigned long long, DID> AddrMap;

struct obj_info
{
	Dwarf_Debug dbg;
	DieMap dies;
	NameMap types;
	AddrMap funcs;

	Dwarf_Unsigned cu_offset;

	DieMap::iterator varIt;
};

// DWARF DIE iteration

static Dwarf_Die
die_first(struct obj_info *o, Dwarf_Die parent)
{
	Dwarf_Die die;
	if (dwarf_child(parent, &die, NULL) == DW_DLV_OK)
		return die;
	return NULL;
}

static Dwarf_Die
die_next(struct obj_info *o, Dwarf_Die cur)
{
	Dwarf_Die next;
	int r = dwarf_siblingof(o->dbg, cur, &next, NULL);
	dwarf_dealloc(o->dbg, cur, DW_DLA_DIE);
	if (r == DW_DLV_OK)
		return next;
	return NULL;
}

// DWARF DIE information

static int
die_tag(Dwarf_Die die)
{
	Dwarf_Half tag;
	dwarf_tag(die, &tag, NULL);
	return tag;
}

static int
die_offset(Dwarf_Die die)
{
	Dwarf_Off off;
	dwarf_dieoffset(die, &off, NULL);
	return off;
}

static char *
die_name(struct obj_info *o, Dwarf_Die die)
{
	char *name, *copy;
	if (dwarf_diename(die, &name, NULL) != DW_DLV_OK)
		return NULL;
	copy = strdup(name);
	dwarf_dealloc(o->dbg, name, DW_DLA_STRING);
	return copy;
}

static DID
die_ref(struct obj_info *o, Dwarf_Die die, Dwarf_Half attr)
{
	Dwarf_Attribute at;
	Dwarf_Off off;
	int r;

	if (dwarf_attr(die, attr, &at, NULL))
		return -1;
	r = dwarf_global_formref(at, &off, NULL);
	assert(r == DW_DLV_OK);
	return off;
}

static Dwarf_Unsigned
die_udata(struct obj_info *o, Dwarf_Die die, Dwarf_Half attr)
{
	Dwarf_Attribute at;
	Dwarf_Unsigned val;
	int r;

	if (dwarf_attr(die, attr, &at, NULL))
		return ~0;
	r = dwarf_formudata(at, &val, NULL);
	assert(r == DW_DLV_OK);
	return val;
}

static Dwarf_Addr
die_addr(struct obj_info *o, Dwarf_Die die, Dwarf_Half attr)
{
	Dwarf_Attribute at;
	Dwarf_Addr val;
	int r;

	if (dwarf_attr(die, attr, &at, NULL))
		return ~0;
	r = dwarf_formaddr(at, &val, NULL);
	assert(r == DW_DLV_OK);
	return val;
}

static Dwarf_Unsigned
die_loc1(struct obj_info *o, Dwarf_Die die, Dwarf_Half attr, Dwarf_Small atom)
{
	Dwarf_Attribute loc;
	Dwarf_Locdesc *llbuf;
	Dwarf_Signed len;
	int r;
	Dwarf_Unsigned out;

	if (dwarf_attr(die, attr, &loc, NULL))
		return ~0;

	r = dwarf_loclist(loc, &llbuf, &len, NULL);
	assert(r == DW_DLV_OK);
	assert(llbuf->ld_s[0].lr_atom == atom);
	out = llbuf->ld_s[0].lr_number;
	dwarf_dealloc(o->dbg, llbuf->ld_s, DW_DLA_LOC_BLOCK);
	dwarf_dealloc(o->dbg, llbuf, DW_DLA_LOCDESC);
	dwarf_dealloc(o->dbg, loc, DW_DLA_ATTR);
	return out;
}

static unsigned long
die_data_member_location(struct obj_info *o, Dwarf_Die die)
{
	return die_loc1(o, die, DW_AT_data_member_location, DW_OP_plus_uconst);
}

// Processed DIE's

enum oi_die_type {
	DIE_TYPE_STRUCT = 1,
	DIE_TYPE_UNION,
	DIE_TYPE_ARRAY,
	DIE_TYPE_REF,
	DIE_TYPE_BASE,
	DIE_VARIABLE,
	DIE_SUBPROGRAM,
};

// XXX Per CU.  Perhaps embed these in struct oi_cu's?  Hmm, but the
// DIE array.  Also, I often don't care (or know) which CU.
struct oi_die
{
	enum oi_die_type type;
	char *name;

	// DIE_TYPE_*
	int size;		/* -1 if incomplete */

	// DIE_TYPE_STRUCT, DIE_TYPE_UNION
	struct oi_field *fields;

	// DIE_TYPE_ARRAY
	int count;

	// DIE_TYPE_REF, DIE_TYPE_ARRAY, DIE_VARIABLE
	DID idtype;

	// DIE_VARIABLE, DIE_SUBPROGRAM
	unsigned long long start;

	// DIE_SUBPROGRAM
	unsigned long long end;
	DID cu;
	DID parent;
};

struct oi_field
{
	char *name;
	int start;
	DID type;
	struct oi_field *next;
};

static void
register_die(struct obj_info *o, DID id, struct oi_die *die)
{
	assert(o->dies.find(id) == o->dies.end());
	o->dies[id] = die;
}

static struct oi_die *
new_die(struct obj_info *o, Dwarf_Die die, enum oi_die_type type)
{
	struct oi_die *d = (struct oi_die*)malloc(sizeof(*d));
	memset(d, 0, sizeof(*d));
	d->type = type;
	d->name = die_name(o, die);
	register_die(o, die_offset(die), d);
	return d;
}

// Type processing

static struct oi_die *
new_type(struct obj_info *o, Dwarf_Die die, enum oi_die_type type)
{
	struct oi_die *t = new_die(o, die, type);
	t->size = die_udata(o, die, DW_AT_byte_size);
	return t;
}

static void
process_type_aggr(struct obj_info *o, Dwarf_Die root, enum oi_die_type type)
{
	assert(type == DIE_TYPE_STRUCT || type == DIE_TYPE_UNION);

	Dwarf_Die die;
	struct oi_die *s = new_type(o, root, type);
	struct oi_field *f, **tail;

	tail = &s->fields;
	for (die = die_first(o, root); die; die = die_next(o, die)) {
		assert(die_tag(die) == DW_TAG_member);
		f = (struct oi_field*)malloc(sizeof(*f));
		*tail = f;
		tail = &f->next;
		*tail = NULL;

		f->name = die_name(o, die);
		f->start = die_data_member_location(o, die);
		f->type = die_ref(o, die, DW_AT_type);
	}
}

static void
process_type_array(struct obj_info *o, Dwarf_Die root)
{
	struct oi_die *t = new_type(o, root, DIE_TYPE_ARRAY);
	t->idtype = die_ref(o, root, DW_AT_type);

	Dwarf_Die sub = die_first(o, root);
	if (die_tag(sub) != DW_TAG_subrange_type) {
		fprintf(stderr, "Array type %#x has no subrange\n", t->idtype);
		abort();
	}
	t->count = die_udata(o, sub, DW_AT_upper_bound) + 1;
}

static void
process_type_ref(struct obj_info *o, Dwarf_Die root)
{
	struct oi_die *t = new_type(o, root, DIE_TYPE_REF);
	t->idtype = die_ref(o, root, DW_AT_type);
	t->count = 1;
}

static void
process_type_base(struct obj_info *o, Dwarf_Die root)
{
	new_type(o, root, DIE_TYPE_BASE);
}

// CU processing

static void
process_variable(struct obj_info *o, Dwarf_Die die)
{
	struct oi_die *v = new_die(o, die, DIE_VARIABLE);
	v->idtype = die_ref(o, die, DW_AT_type);
	v->start = die_loc1(o, die, DW_AT_location, DW_OP_addr);
}

static void
process_subprogram(struct obj_info *o, Dwarf_Die die, DID cuid, DID parent)
{
	if (die_tag(die) == DW_TAG_subprogram ||
	    die_tag(die) == DW_TAG_inlined_subroutine) {
		struct oi_die *d = new_die(o, die, DIE_SUBPROGRAM);
		DID origin = die_ref(o, die, DW_AT_abstract_origin);
		if (origin != -1)
			d->name = strdup(o->dies[origin]->name);
		d->start = die_addr(o, die, DW_AT_low_pc);
		d->end = die_addr(o, die, DW_AT_high_pc);
		d->cu = cuid;
		d->parent = parent;
//		printf("%x %s %llx %llx\n", die_offset(die), d->name, d->start, d->end);

		parent = die_offset(die);
	}

	for (die = die_first(o, die); die; die = die_next(o, die))
		process_subprogram(o, die, cuid, parent);
}

static void
process_global(struct obj_info *o, Dwarf_Die gl, DID cuid)
{
	switch (die_tag(gl)) {
	case DW_TAG_structure_type:
		process_type_aggr(o, gl, DIE_TYPE_STRUCT);
		break;

	case DW_TAG_union_type:
		process_type_aggr(o, gl, DIE_TYPE_UNION);
		break;

	case DW_TAG_array_type:
		process_type_array(o, gl);
		break;

	case DW_TAG_typedef:
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
		process_type_ref(o, gl);
		break;

	case DW_TAG_base_type:
	case DW_TAG_class_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
//	case DW_TAG_string_type:
//	case DW_TAG_subroutine_type:
//	case DW_TAG_ptr_to_member_type:
//	case DW_TAG_set_type:
//	case DW_TAG_subrange_type:
//	case DW_TAG_file_type:
//	case DW_TAG_packed_type:
//	case DW_TAG_thrown_type:
//	case DW_TAG_template_type_parameter:
//	case DW_TAG_template_value_parameter:
		process_type_base(o, gl);
		break;

	case DW_TAG_variable:
		process_variable(o, gl);
		break;

	case DW_TAG_subprogram:
		// XXX We're using addr2line now, so don't waste time
		// gathering subprogram information.
		break;

		process_subprogram(o, gl, cuid, 0);
		break;

	default:
		break;
	}
}

static void
process_cu(struct obj_info *o, Dwarf_Die cu, int level)
{
	Dwarf_Die die;
	DID cuid = die_offset(cu);
	assert(die_tag(cu) == DW_TAG_compile_unit);
	for (die = die_first(o, cu); die; die = die_next(o, die))
		process_global(o, die, cuid);
}

static void
print_die(struct obj_info *o, Dwarf_Die die, int indent)
{
	const char *tag_name;
	char *name;
	int tag = die_tag(die);
	dwarf_get_TAG_name(tag, &tag_name);
	printf("%*s <%x> %s", indent, "", die_offset(die), tag_name);
	if (dwarf_diename(die, &name, NULL) == DW_DLV_OK) {
		printf(" %s", name);
		dwarf_dealloc(o->dbg, name, DW_DLA_STRING);
	}
	if (tag == DW_TAG_member)
		printf(" <%x> %lu", die_ref(o, die, DW_AT_type),
		       die_data_member_location(o, die));
	printf("\n");
}

__attribute__((used)) static void
print_die_rec(struct obj_info *o, Dwarf_Die root, int level)
{
	Dwarf_Die die;

	print_die(o, root, level);

	for (die = die_first(o, root); die; die = die_next(o, die))
		print_die_rec(o, die, level+1);
}

static void
obj_info_process(struct obj_info *o)
{
	Dwarf_Error error;

	o->cu_offset = 0;
	while (1) {
		Dwarf_Unsigned next_cu_offset;
		Dwarf_Die root;
		int r;

		r = dwarf_next_cu_header_b
			(o->dbg, NULL, NULL, NULL, NULL /* address_size */,
			 NULL, NULL, &next_cu_offset, &error);
		if (r == DW_DLV_ERROR) {
			fprintf(stderr, "%s: dwarf_next_cu_header\n", __func__);
			exit(1);
		}
		if (r == DW_DLV_NO_ENTRY)
			break;

		// Get the root DIE of this CU
		r = dwarf_siblingof(o->dbg, NULL, &root, &error);
		if (r == DW_DLV_ERROR) {
			fprintf(stderr, "%s: dwarf_siblingof\n", __func__);
			exit(1);
		}
		assert(r == DW_DLV_OK);
		process_cu(o, root, 0);
		dwarf_dealloc(o->dbg, root, DW_DLA_DIE);
		o->cu_offset = next_cu_offset;
	}

	// Construct indexes
	for (DieMap::iterator it = o->dies.begin(); it != o->dies.end(); it++) {
		struct oi_die *d = it->second;
		switch (d->type) {
		case DIE_TYPE_STRUCT:
		case DIE_TYPE_UNION:
		case DIE_TYPE_ARRAY:
		case DIE_TYPE_REF:
		case DIE_TYPE_BASE:
			if (d->size >= 0 && d->name)
				o->types[d->name] = it->first;
			break;

		case DIE_SUBPROGRAM:
			if (d->start != ~0ull)
				o->funcs[d->start] = it->first;

		default:
			break;
		}
	}
}

int
obj_info_type_by_name(struct obj_info *o, const char *name)
{
	NameMap::iterator it = o->types.find(name);
	if (it == o->types.end())
		return -1;
	return it->second;
}

unsigned int
obj_info_type_size(struct obj_info *o, int idtype)
{
	int mul = 1;
	while (idtype != -1 && o->dies[idtype]) {
		switch (o->dies[idtype]->type) {
		case DIE_TYPE_ARRAY:
			mul *= o->dies[idtype]->count;
		case DIE_TYPE_REF:
			idtype = o->dies[idtype]->idtype;
			break;
		case DIE_TYPE_STRUCT:
		case DIE_TYPE_UNION:
		case DIE_TYPE_BASE:
			return mul * o->dies[idtype]->size;
		default:
			fprintf(stderr, "type_size: non-type DIE %#x\n",
				idtype);
			abort();
		}
	}
	fprintf(stderr, "type_size: bad DIE %#x\n", idtype);
	abort();
}

static int
offset_name_type(struct obj_info *o, int id, char *out, int len)
{
	struct oi_die *t = o->dies[id];
	int n;

	switch (t->type) {
	case DIE_TYPE_STRUCT:
		snprintf(out, len, "{struct %s}", t->name);
		break;
	case DIE_TYPE_UNION:
		snprintf(out, len, "{union %s}", t->name);
		break;
	case DIE_TYPE_ARRAY:
		id = offset_name_type(o, t->idtype, out, len);
		n = strlen(out) - 1;
		snprintf(out + n, len - n, "[]}");
		break;
	case DIE_TYPE_REF:
	case DIE_TYPE_BASE:
		snprintf(out, len, "{%s}", t->name);
		break;
	case DIE_VARIABLE:
		n = snprintf(out, len, "%s", t->name);
		id = t->idtype;
		break;

	default:
		fprintf(stderr, "obj_info_offset_name: bad DIE type %d\n",
			t->type);
		abort();
	}
	return id;
}

static int
offset_name_field(struct obj_info *o, int id, int off,
		  char *out, int len)
{
	int n = 0;
	struct oi_die *t = o->dies[id];

	switch (t->type) {
	case DIE_TYPE_STRUCT:
	{
		struct oi_field *f, *l;
		for (f = l = t->fields; l; l = f, f = f->next) {
			// XXX Assumes ordering
			if (!f || off < f->start)
				break;
		}
		assert(l);
		n += snprintf(out + n, len - n, ".%s", l->name ?: "<anon>");
		return offset_name_field(o, l->type, off - l->start,
					 out + n, len - n);
	}

	case DIE_TYPE_UNION:
	{
		n += snprintf(out + n, len - n, ".(");

		int i = 0;
		struct oi_field *f;
		for (f = t->fields; f; f = f->next) {
			if (off >= (int)obj_info_type_size(o, f->type))
				continue;
			if (i++ > 0)
				n += snprintf(out + n, len - n, "|");
			n += snprintf(out + n, len - n, "%s", f->name ?: "<anon>");
			offset_name_field(o, f->type, off, out + n, len - n);
			n += strlen(out + n);
		}
		n += snprintf(out + n, len - n, ")");
		if (i)
			return 0;
		return off;
	}

	case DIE_TYPE_ARRAY:
	{
		unsigned int esize = obj_info_type_size(o, t->idtype);
		n += snprintf(out + n, len - n, "[%d]", off/esize);
		return offset_name_field(o, t->idtype, off - (off/esize)*esize,
					 out + n, len - n);
	}

	case DIE_TYPE_REF:
		return offset_name_field(o, t->idtype, off, out, len);

	case DIE_TYPE_BASE:
		return off;

	default:
		fprintf(stderr, "%s: unexpected DIE type %d\n",
			__func__, t->type);
		abort();
	}
}

void
obj_info_offset_name(struct obj_info *o, int id, int off,
		     char *out, int len)
{
	int n;

	id = offset_name_type(o, id, out, len);
	n = strlen(out);
	off = offset_name_field(o, id, off, out+n, len-n);
	n = strlen(out);

	if (off)
		snprintf(out + n, len - n, "+%#x", off);
}

void
obj_info_vars_reset(struct obj_info *o)
{
	o->varIt = o->dies.begin();
}

int
obj_info_vars_next(struct obj_info *o, struct obj_info_var *var)
{
	while (o->varIt != o->dies.end() &&
	       !(o->varIt->second->type == DIE_VARIABLE &&
		 o->varIt->second->start != ~0ull))
		o->varIt++;
	if (o->varIt == o->dies.end())
		return 0;

	struct oi_die *d = o->varIt->second;
	var->id = o->varIt->first;
	var->name = d->name;
	var->location = d->start;
	var->idtype = d->idtype;

	o->varIt++;
	return 1;
}

static struct oi_die *
pc_to_func(struct obj_info *o, unsigned long long pc)
{
	AddrMap::iterator it = o->funcs.upper_bound(pc);
	if (it == o->funcs.begin())
		return NULL;
	it--;

	struct oi_die *d = o->dies[it->second];
	assert(d->type == DIE_SUBPROGRAM);
	while (1) {
		// XXX Ugh, can also be DW_AT_ranges
		if (d->start != ~0ull) {
			assert(d->start <= pc);
			if (pc < d->end)
				return d;
		}
		if (!d->parent)
			return NULL;
		d = o->dies[d->parent];
	}
}

int
obj_info_pc_info(struct obj_info *o, unsigned long long pc,
		 char **name, char **fname, int *fline)
{
	int r;

	// Find the function containing pc
	struct oi_die *d = pc_to_func(o, pc);
	if (!d)
		return -1;
	*name = strdup(d->name);

	// Get the CU containing this function
	Dwarf_Die cu;
	r = dwarf_offdie(o->dbg, d->cu, &cu, NULL);
	assert(r == DW_DLV_OK);

	// Get the line number information for this CU
	Dwarf_Line *linebuf;
	Dwarf_Signed nlines;
	r = dwarf_srclines(cu, &linebuf, &nlines, NULL);
	assert(r == DW_DLV_OK);

	// Find the line number record for this PC
	int i;
	for (i = 0; i < nlines; ++i) {
		Dwarf_Addr addr;
		r = dwarf_lineaddr(linebuf[i], &addr, NULL);
		assert(r == DW_DLV_OK);
		if (addr > pc)
			break;
	}
	assert(i);

	// Get the source file name
	char *linesrc;
	r = dwarf_linesrc(linebuf[i-1], &linesrc, NULL);
	assert(r == DW_DLV_OK);
	*fname = strdup(linesrc);
	dwarf_dealloc(o->dbg, linesrc, DW_DLA_STRING);

	// Get the line number
	Dwarf_Unsigned lineno;
	r = dwarf_lineno(linebuf[i-1], &lineno, NULL);
	assert(r == DW_DLV_OK);
	*fline = lineno;

	// XXX Cache linebuf?
	dwarf_srclines_dealloc(o->dbg, linebuf, nlines);

	return 0;
}

struct obj_info*
obj_info_create_from_fd(int fd)
{
	struct obj_info *out = new struct obj_info;
	Dwarf_Error err;
	int r;

	r = dwarf_init(fd, DW_DLC_READ, 0, 0, &out->dbg, &err);
	if (r != DW_DLV_OK) {
		fprintf(stderr, "%s: dwarf_init", __func__);
		return NULL;
	}
	obj_info_process(out);
	return out;
}

void
obj_info_destroy(struct obj_info *o)
{
	if (!o)
		return;
	dwarf_finish(o->dbg, NULL);
	delete o;
}

#if TEST
int
main(int argc, char **argv)
{
	char str[128];
	if (argc != 2) {
		fprintf(stderr, "usage: %s elf-file\n", argv[0]);
		return 2;
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
		return 1;
	}
	struct obj_info *o = obj_info_create_from_fd(fd);
	obj_info_offset_name(o, obj_info_type_by_name(o, "vm_area_struct"), 80, str, sizeof str);
	printf("%s\n", str);
	obj_info_offset_name(o, obj_info_type_by_name(o, "vm_area_struct"), 80+24, str, sizeof str);
	printf("%s\n", str);
	obj_info_offset_name(o, 0x1f315, 4, str, sizeof str);
	printf("%s\n", str);
	obj_info_offset_name(o, obj_info_type_by_name(o, "dentry")/*0x2a3ac*/ /*dentry*/, 209, str, sizeof str);
	printf("%s\n", str);

	// struct obj_info_var var;
	// obj_info_vars_reset(o);
	// while (obj_info_vars_next(o, &var))
	// 	printf("%s %llx %d\n", var.name, var.location, obj_info_type_size(o, var.idtype));

	// char *funcname, *filename;
	// int fileline;
	// obj_info_pc_info(o, 0xffffffff810343d5ull,
	// 		 &funcname, &filename, &fileline);
	// printf("%s %s:%d\n", funcname, filename, fileline);
	// free(funcname);
	// free(filename);

	obj_info_destroy(o);
	return 0;
}
#endif
