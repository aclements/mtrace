#ifndef _OBJINFO_H
#define _OBJINFO_H

struct obj_info;

struct obj_info*
obj_info_create_from_fd(int fd);
void
obj_info_destroy(struct obj_info *o);

int
obj_info_lookup_struct_offset(struct obj_info *o, const char *tname, int off,
			      char *out, int len);
int
obj_info_next_variable(struct obj_info *o, int *pos,
		       const char **nameOut, unsigned long long *startOut,
		       unsigned int *sizeOut);

#endif // _OBJINFO_H
