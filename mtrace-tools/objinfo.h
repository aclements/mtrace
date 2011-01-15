#ifndef _OBJINFO_H
#define _OBJINFO_H

#ifdef __cplusplus
extern "C" {
#endif

    struct obj_info;

    struct obj_info*
    obj_info_create_from_fd(int fd);
    void
    obj_info_destroy(struct obj_info *o);

    int
    obj_info_lookup_struct_offset(struct obj_info *o, const char *tname, int off,
                                  char *out, int len);

    unsigned int
    obj_info_type_size(struct obj_info *o, int idtype);

    struct obj_info_var 
    {
        const char *name;
        unsigned long long location;
        int idtype;
    };

    void
    obj_info_vars_reset(struct obj_info *o);
    int
    obj_info_vars_next(struct obj_info *o, struct obj_info_var *var);

#ifdef __cplusplus
}
#endif

#endif // _OBJINFO_H
