/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * SELinux ss/ structure layouts used by the built-in policy snapshot
 * (selinux_sepolicy.c) and by the 4.9 - 4.18 legacy evaluator
 * (selinux_hide_legacy.c).  Layouts follow 4.9 - 4.18; every field we touch is
 * read through these copies, so a wrong guess shows up as a probe failure, not
 * as silent corruption.
 */

#ifndef _KP_SELINUX_SS_H_
#define _KP_SELINUX_SS_H_

#include <ktypes.h>

/* ---- SELinux ss/ structures (layouts from the kpm selinux_hook module) ---- */

struct policy_file
{
    char *data;
    size_t len;
};

struct flex_array;
struct hashtab;

struct symtab
{
    struct hashtab *table;
    u32 nprim;
};

enum
{
    SELINUX_EBITMAP_NODE_SIZE = 64,
    SELINUX_EBITMAP_UNIT_BITS = sizeof(unsigned long) * 8,
    SELINUX_EBITMAP_UNIT_NUMS = (SELINUX_EBITMAP_NODE_SIZE - sizeof(void *) - sizeof(u32)) /
                                sizeof(unsigned long),
};

struct ebitmap_node
{
    struct ebitmap_node *next;
    unsigned long maps[SELINUX_EBITMAP_UNIT_NUMS];
    u32 startbit;
};

struct ebitmap
{
    struct ebitmap_node *node;
    u32 highbit;
};

struct mls_level
{
    u32 sens;
    struct ebitmap cat;
};

struct mls_range
{
    struct mls_level level[2];
};

struct context
{
    u32 user;
    u32 role;
    u32 type;
    u32 len;
    struct mls_range range;
    char *str;
    u32 hash;
};

struct constraint_expr
{
    u32 expr_type;
    u32 attr;
    u32 op;
    struct ebitmap names;
    struct type_set *type_names;
    struct constraint_expr *next;
};

struct constraint_node
{
    u32 permissions;
    struct constraint_expr *expr;
    struct constraint_node *next;
};

struct common_datum
{
    u32 value;
    struct symtab permissions;
};

struct class_datum
{
    u32 value;
    char *comkey;
    struct common_datum *comdatum;
    struct symtab permissions;
    struct constraint_node *constraints;
    struct constraint_node *validatetrans;
    char default_user;
    char default_role;
    char default_type;
    char default_range;
};

struct role_datum
{
    u32 value;
    u32 bounds;
    struct ebitmap dominates;
    struct ebitmap types;
};

struct role_trans
{
    u32 role;
    u32 type;
    u32 tclass;
    u32 new_role;
    struct role_trans *next;
};

struct filename_trans
{
    u32 stype;
    u32 ttype;
    u16 tclass;
    const char *name;
};

struct role_allow
{
    u32 role;
    u32 new_role;
    struct role_allow *next;
};

struct type_datum
{
    u32 value;
    u32 bounds;
    unsigned char primary;
    unsigned char attribute;
};

struct user_datum
{
    u32 value;
    u32 bounds;
    struct ebitmap roles;
    struct mls_range range;
    struct mls_level dfltlevel;
};

struct level_datum
{
    struct mls_level *level;
    unsigned char isalias;
};

struct cat_datum
{
    u32 value;
    unsigned char isalias;
};

struct range_trans
{
    u32 source_type;
    u32 target_type;
    u32 target_class;
};

struct cond_bool_datum
{
    u32 value;
    int state;
};

struct cond_node;

struct type_set
{
    struct ebitmap types;
    struct ebitmap negset;
    u32 flags;
};

struct ocontext
{
    union
    {
        char *name;
        struct
        {
            u8 protocol;
            u16 low_port;
            u16 high_port;
        } port;
        struct
        {
            u32 addr;
            u32 mask;
        } node;
        struct
        {
            u32 addr[4];
            u32 mask[4];
        } node6;
        struct
        {
            u64 subnet_prefix;
            u16 low_pkey;
            u16 high_pkey;
        } ibpkey;
        struct
        {
            char *dev_name;
            u8 port;
        } ibendport;
    } u;
    union
    {
        u32 sclass;
        u32 behavior;
    } v;
    struct context context[2];
    u32 sid[2];
    struct ocontext *next;
};

struct genfs
{
    char *fstype;
    struct ocontext *head;
    struct genfs *next;
};

struct avtab_key
{
    u16 source_type;
    u16 target_type;
    u16 target_class;
    u16 specified;
};

#define AVTAB_ALLOWED 0x0001
#define AVTAB_AUDITALLOW 0x0002
#define AVTAB_AUDITDENY 0x0004
#define AVTAB_AV (AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY)
#define AVTAB_ENABLED 0x8000
#define AVTAB_XPERMS_ALLOWED 0x0100
#define AVTAB_XPERMS_AUDITALLOW 0x0200
#define AVTAB_XPERMS_DONTAUDIT 0x0400
#define AVTAB_XPERMS (AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT)

/* Layout of struct extended_perms_data (8 x u32); declared locally so this
 * header does not depend on the security.h include order.  It is only ever a
 * pointer target: xperms are never requested by the queries we answer. */
struct kp_extended_perms_data
{
    u32 p[8];
};

struct avtab_extended_perms
{
    u8 specified;
    u8 driver;
    struct kp_extended_perms_data perms;
};

struct avtab_datum
{
    union
    {
        u32 data;
        struct avtab_extended_perms *xperms;
    } u;
};

struct avtab_node
{
    struct avtab_key key;
    struct avtab_datum datum;
    struct avtab_node *next;
};

struct avtab
{
    struct flex_array *htable;
    u32 nel;
    u32 nslot;
    u32 mask;
};

#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES 2
#define SYM_TYPES 3
#define SYM_USERS 4
#define SYM_BOOLS 5
#define SYM_LEVELS 6
#define SYM_CATS 7
#define SYM_NUM 8
#define OCON_ISID 0
#define OCON_FS 1
#define OCON_PORT 2
#define OCON_NETIF 3
#define OCON_NODE 4
#define OCON_FSUSE 5
#define OCON_NODE6 6
#define OCON_IBPKEY 7
#define OCON_IBENDPORT 8
#define OCON_NUM 9

/* Type declarations only: the policydb itself is written and read by the
 * kernel's own policydb_read()/policydb_load_isids(), which use the kernel's
 * layout.  Nothing here is dereferenced field by field. */
#define KP_POLICYDB_TAIL \
    struct symtab symtab[SYM_NUM]; \
    struct flex_array *sym_val_to_name[SYM_NUM]; \
    struct class_datum **class_val_to_struct; \
    struct role_datum **role_val_to_struct; \
    struct user_datum **user_val_to_struct; \
    struct flex_array *type_val_to_struct_array; \
    struct avtab te_avtab; \
    struct role_trans *role_tr; \
    struct ebitmap filename_trans_ttypes; \
    struct hashtab *filename_trans; \
    struct cond_bool_datum **bool_val_to_struct; \
    struct avtab te_cond_avtab; \
    struct cond_node *cond_list; \
    struct role_allow *role_allow;
/* Everything from ocontexts[] on is version dependent (OCON_NUM grew from 5 to
 * 7 to 9 slots) and is read through explicit offsets in kp_fill_tail(); keeping
 * it in this struct would only invite reads at a wrong offset. */

struct policydb
{
    int mls_enabled;
    int android_netlink_route;
    int android_netlink_getneigh;

    KP_POLICYDB_TAIL
};

/* Convenience aliases, shared by both layouts above. */
#define p_commons symtab[SYM_COMMONS]
#define p_classes symtab[SYM_CLASSES]
#define p_roles symtab[SYM_ROLES]
#define p_types symtab[SYM_TYPES]
#define p_users symtab[SYM_USERS]
#define p_bools symtab[SYM_BOOLS]
#define p_levels symtab[SYM_LEVELS]
#define p_cats symtab[SYM_CATS]



/* sidtab entry (only the leading fields are used: sid + context). */
struct sidtab_entry
{
    u32 sid;
    struct context context;
    struct hlist_node hash;
    struct sidtab_entry *next;
};

#endif
