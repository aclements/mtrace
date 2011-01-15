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
	union oi_type **types;
	int ntypes;

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

static int
die_byte_size(struct obj_info *o, Dwarf_Die die)
{
	Dwarf_Attribute at;
	Dwarf_Unsigned val;
	int r;

	if (dwarf_attr(die, DW_AT_byte_size, &at, NULL))
		return -1;
	r = dwarf_formudata(at, &val, NULL);
	assert(r == DW_DLV_OK);
	return val;
}

static unsigned long
die_data_member_location(struct obj_info *o, Dwarf_Die die)
{
	Dwarf_Attribute loc;
	Dwarf_Locdesc *llbuf;
	Dwarf_Signed len;
	int r;
	unsigned long out;

	if (dwarf_attr(die, DW_AT_data_member_location, &loc, NULL))
		return ~0;

	r = dwarf_loclist(loc, &llbuf, &len, NULL);
	assert(r == DW_DLV_OK);
	assert(llbuf->ld_s[0].lr_atom == DW_OP_plus_uconst);
	out = llbuf->ld_s[0].lr_number;
	dwarf_dealloc(o->dbg, llbuf->ld_s, DW_DLA_LOC_BLOCK);
	dwarf_dealloc(o->dbg, llbuf, DW_DLA_LOCDESC);
	dwarf_dealloc(o->dbg, loc, DW_DLA_ATTR);
	return out;
}

// Type processing

enum oi_type_type {
	TYPE_STRUCT = 1,
	TYPE_OTHER,
};

struct oi_type_common
{
	enum oi_type_type type;
	char *name;
	int size;		/* -1 if incomplete */
};

// XXX Per CU.  Perhaps embed these in struct oi_cu's?  Hmm, but the
// type array.  Also, I often don't care (or know) which CU.
struct oi_struct
{
	struct oi_type_common c;
	struct oi_field *fields;
};

struct oi_field
{
	char *name;
	int start;
	int type;
	struct oi_field *next;
};

union oi_type
{
	struct oi_type_common c;

	struct oi_struct tstruct;
};

static void
register_type(struct obj_info *o, int id, union oi_type *type)
{
	while (id > o->ntypes) {
		int n = o->ntypes ? o->ntypes * 2 : 16;
		o->types = realloc(o->types, n * sizeof(*o->types));
		memset(o->types + o->ntypes, 0,
		       (n - o->ntypes) * sizeof(*o->types));
		o->ntypes  = n;
	}
	assert(!o->types[id]);
	o->types[id] = type;
}

static void
process_type_generic(struct obj_info *o, Dwarf_Die die,
		     enum oi_type_type type, struct oi_type_common *t)
{
	t->type = type;
	t->name = die_name(o, die);
	t->size = die_byte_size(o, die);
	register_type(o, die_offset(die), (union oi_type*)t);
}

static void
process_type_struct(struct obj_info *o, Dwarf_Die root)
{
	Dwarf_Die die;
	struct oi_struct *s = malloc(sizeof(*s));
	struct oi_field *f, **tail;

	memset(s, 0, sizeof(*s));
	process_type_generic(o, root, TYPE_STRUCT, &s->c);

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
process_type_other(struct obj_info *o, Dwarf_Die root)
{
	struct oi_type_common *t = malloc(sizeof(*t));

	memset(t, 0, sizeof(*t));
	process_type_generic(o, root, TYPE_OTHER, t);
}

// CU processing

static void
process_variable(struct obj_info *o, Dwarf_Die die)
{
	
}

static void
process_global(struct obj_info *o, Dwarf_Die gl, int level)
{
	switch (die_tag(gl)) {
	case DW_TAG_structure_type:
		process_type_struct(o, gl);
		break;
	case DW_TAG_array_type:
	case DW_TAG_class_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	case DW_TAG_string_type:
	case DW_TAG_subroutine_type:
	case DW_TAG_typedef:
	case DW_TAG_union_type:
	case DW_TAG_ptr_to_member_type:
	case DW_TAG_set_type:
	case DW_TAG_subrange_type:
	case DW_TAG_base_type:
	case DW_TAG_const_type:
	case DW_TAG_file_type:
	case DW_TAG_packed_type:
	case DW_TAG_thrown_type:
	case DW_TAG_volatile_type:
	case DW_TAG_template_type_parameter:
	case DW_TAG_template_value_parameter:
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

static union oi_type *
type_by_name(struct obj_info *o, const char *name)
{
	// XXX This is stupid slow
	int i;
	for (i = 0; i < o->ntypes; ++i)
		if (o->types[i] && o->types[i]->c.size >= 0 &&
		    o->types[i]->c.name &&
		    strcmp(o->types[i]->c.name, name) == 0)
			return o->types[i];
	return NULL;
}

// XXX Unions
int
obj_info_lookup_struct_offset(struct obj_info *o, const char *tname, int off,
			      char *out, int len)
{
	int n;
	union oi_type *t = type_by_name(o, tname);
	if (!t || t->c.type != TYPE_STRUCT)
		return -1;

	n = snprintf(out, len, "struct %s", t->c.name);
	while (t) {
		if (t->c.type != TYPE_STRUCT)
			break;
		struct oi_struct *s = &t->tstruct;
		struct oi_field *f, *l;
		for (f = l = s->fields; l; l = f, f = f->next) {
			// XXX Assumes ordering
			if (!f || off < f->start) {
				assert(l);
				n += snprintf(out + n, len - n, ".%s", l->name);
				break;
			}
		}
		assert(l);
		off -= l->start;
		t = o->types[l->type];
	}
	if (off)
		snprintf(out + n, len - n, "+%#x", off);
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
	obj_info_destroy(o);
	return 0;
}
#endif
