// -*- c-file-style: "linux"; indent-tabs-mode: t -*-

#include "objinfo.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dwarf.h>
#include <libdwarf.h>

struct obj_info
{
	Dwarf_Debug dbg;
	struct oi_die **dies;
	int ndies;

	Dwarf_Unsigned cu_offset;
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

static int
die_type(struct obj_info *o, Dwarf_Die die)
{
	Dwarf_Attribute at;
	Dwarf_Off off;
	int r;

	if (dwarf_attr(die, DW_AT_type, &at, NULL))
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
	DIE_TYPE_REF,
	DIE_TYPE_OTHER,
	DIE_VARIABLE,
};

// XXX Per CU.  Perhaps embed these in struct oi_cu's?  Hmm, but the
// DIE array.  Also, I often don't care (or know) which CU.
struct oi_die
{
	enum oi_die_type type;
	char *name;

	// DIE_TYPE_*
	int size;		/* -1 if incomplete */

	// DIE_TYPE_STRUCT
	struct oi_field *fields;

	// DIE_TYPE_REF
	int count;

	// DIE_TYPE_REF, DIE_TYPE_ARRAY, DIE_VARIABLE
	int typeid;

	// DIE_VARIABLE
	unsigned long long location;
};

struct oi_field
{
	char *name;
	int start;
	int type;
	struct oi_field *next;
};

static void
register_die(struct obj_info *o, int id, struct oi_die *die)
{
	while (id > o->ndies) {
		int n = o->ndies ? o->ndies * 2 : 16;
		o->dies = realloc(o->dies, n * sizeof(*o->dies));
		memset(o->dies + o->ndies, 0,
		       (n - o->ndies) * sizeof(*o->dies));
		o->ndies  = n;
	}
	assert(!o->dies[id]);
	o->dies[id] = die;
}

static struct oi_die *
new_die(struct obj_info *o, Dwarf_Die die, enum oi_die_type type)
{
	struct oi_die *d = malloc(sizeof(*d));
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
process_type_struct(struct obj_info *o, Dwarf_Die root)
{
	Dwarf_Die die;
	struct oi_die *s = new_type(o, root, DIE_TYPE_STRUCT);
	struct oi_field *f, **tail;

	tail = &s->fields;
	for (die = die_first(o, root); die; die = die_next(o, die)) {
		assert(die_tag(die) == DW_TAG_member);
		f = malloc(sizeof(*f));
		*tail = f;
		tail = &f->next;
		*tail = NULL;

		f->name = die_name(o, die);
		f->start = die_data_member_location(o, die);
		f->type = die_type(o, die);
	}
}

static void
process_type_array(struct obj_info *o, Dwarf_Die root)
{
	struct oi_die *t = new_type(o, root, DIE_TYPE_REF);
	t->typeid = die_type(o, root);

	Dwarf_Die sub = die_first(o, root);
	if (die_tag(sub) == DW_TAG_subrange_type)
		t->count = die_udata(o, sub, DW_AT_upper_bound) + 1;
}

static void
process_type_ref(struct obj_info *o, Dwarf_Die root)
{
	struct oi_die *t = new_type(o, root, DIE_TYPE_REF);
	t->typeid = die_type(o, root);
	t->count = 1;
}

static void
process_type_other(struct obj_info *o, Dwarf_Die root)
{
	new_type(o, root, DIE_TYPE_OTHER);
}

// CU processing

static void
process_variable(struct obj_info *o, Dwarf_Die die)
{
	struct oi_die *v = new_die(o, die, DIE_VARIABLE);
	v->typeid = die_type(o, die);
	v->location = die_loc1(o, die, DW_AT_location, DW_OP_addr);
}

static void
process_global(struct obj_info *o, Dwarf_Die gl, int level)
{
	switch (die_tag(gl)) {
	case DW_TAG_structure_type:
		process_type_struct(o, gl);
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
	case DW_TAG_union_type:	/* XXX */
//	case DW_TAG_ptr_to_member_type:
//	case DW_TAG_set_type:
//	case DW_TAG_subrange_type:
//	case DW_TAG_file_type:
//	case DW_TAG_packed_type:
//	case DW_TAG_thrown_type:
//	case DW_TAG_template_type_parameter:
//	case DW_TAG_template_value_parameter:
		process_type_other(o, gl);
		break;

	case DW_TAG_variable:
		process_variable(o, gl);
		break;

	default:
		break;
	}
}

static void
process_cu(struct obj_info *o, Dwarf_Die cu, int level)
{
	Dwarf_Die die;
	assert(die_tag(cu) == DW_TAG_compile_unit);
	for (die = die_first(o, cu); die; die = die_next(o, die))
		process_global(o, die, level+1);
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
		printf(" <%x> %lu", die_type(o, die),
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
}

static struct oi_die *
type_by_name(struct obj_info *o, const char *name)
{
	// XXX This is stupid slow
	int i;
	for (i = 0; i < o->ndies; ++i)
		if (o->dies[i] && o->dies[i]->size >= 0 &&
		    o->dies[i]->name &&
		    strcmp(o->dies[i]->name, name) == 0)
			return o->dies[i];
	return NULL;
}

static unsigned int
type_size(struct obj_info *o, int typeid)
{
	int mul = 1;
	while (typeid != -1 && o->dies[typeid]) {
		switch (o->dies[typeid]->type) {
		case DIE_TYPE_REF:
			mul *= o->dies[typeid]->count;
			typeid = o->dies[typeid]->typeid;
			break;
		case DIE_TYPE_STRUCT:
		case DIE_TYPE_OTHER:
			return mul * o->dies[typeid]->size;
		default:
			fprintf(stderr, "type_size: non-type DIE %#x\n",
				typeid);
			abort();
		}
	}
	fprintf(stderr, "type_size: bad DIE %#x\n", typeid);
	abort();
}

// XXX Unions
int
obj_info_lookup_struct_offset(struct obj_info *o, const char *tname, int off,
			      char *out, int len)
{
	int n;
	struct oi_die *t = type_by_name(o, tname);
	if (!t || t->type != DIE_TYPE_STRUCT)
		return -1;

	n = snprintf(out, len, "struct %s", t->name);
	while (t) {
		if (t->type != DIE_TYPE_STRUCT)
			break;
		struct oi_field *f, *l;
		for (f = l = t->fields; l; l = f, f = f->next) {
			// XXX Assumes ordering
			if (!f || off < f->start) {
				assert(l);
				n += snprintf(out + n, len - n, ".%s", l->name);
				break;
			}
		}
		assert(l);
		off -= l->start;
		t = o->dies[l->type];
	}
	if (off)
		snprintf(out + n, len - n, "+%#x", off);
	return 0;
}

int
obj_info_next_variable(struct obj_info *o, int *pos,
		       const char **nameOut, unsigned long long *startOut,
		       unsigned int *sizeOut)
{
	for (; *pos < o->ndies; (*pos)++) {
		struct oi_die *d = o->dies[*pos];
		if (d && d->type == DIE_VARIABLE && d->location != ~0ull) {
			*nameOut = d->name;
			*startOut = d->location;
			*sizeOut = type_size(o, d->typeid);
			(*pos)++;
			return 1;
		}
	}
	return 0;
}

struct obj_info*
obj_info_create_from_fd(int fd)
{
	struct obj_info *out = malloc(sizeof(*out));
	Dwarf_Error err;
	int r;

	memset(out, 0, sizeof(*out));

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
	free(o);
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
	//obj_info_print_struct_offset(o, "vm_area_struct", 56, str, sizeof str);
	obj_info_lookup_struct_offset(o, "dentry", 104, str, sizeof str);
	printf("%s\n", str);

	int pos = 0;
	const char *name;
	unsigned long long start;
	unsigned int size;
	while (obj_info_next_variable(o, &pos, &name, &start, &size))
		printf("%s %llx %d\n", name, start, size);

	obj_info_destroy(o);
	return 0;
}
#endif