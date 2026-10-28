/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * Legacy backend for selinux_hide: 4.9 - 4.18.
 *
 * Those kernels have no policydb argument in the ss/ helpers.  Upstream 4.9 and
 * 4.14 keep the policy database in globals (policydb, sidtab), and even the
 * functions that DO take a policydb on later kernels -- constraint_expr_eval()
 * and type_attribute_bounds_av() -- read the global directly, so they cannot be
 * pointed at our copy.  Swapping the global for the duration of a query would
 * make every other CPU evaluate live contexts against our copy, which faults as
 * soon as the manager's policy carries type ids beyond the copy's table.
 *
 * So this backend evaluates the decision itself, exactly like the ss/ code it
 * replaces, but over an explicit policydb:
 *
 *   - avtab:            avtab_search_node()/avtab_search_node_next() and
 *                       cond_compute_av() take the table explicitly (real kernel
 *                       code, not reimplemented)
 *   - ebitmap:          ebitmap_get_bit()/ebitmap_cmp()/ebitmap_contains(), plus
 *                       the traversal macro's own logic
 *   - flex_array:       flex_array_get()/flex_array_get_ptr()
 *   - constraints:      constraint_expr_eval() ported line by line, because the
 *                       original reads the global policydb
 *   - type bounds:      type_attribute_bounds_av() ported, same reason
 *   - rendering:        context_struct_to_string() reads the global policydb for
 *                       every name, so contexts of the copy are rendered here
 *
 * Everything else is shared with the main backend: the same deep copy
 * (selinux_sepolicy.c), the same selinuxfs hooks and the same fake status page.
 * A decision computed here is therefore the decision the stock kernel would
 * have made on the unmodified policy, which is what makes the feature honest
 * instead of a string filter.
 *
 * Every symbol above is looked up at runtime; if one is missing the backend
 * refuses to install (and logs why) rather than guessing.
 */

#include <selinux_hide.h>
#include <selinux_sepolicy.h>

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <kputils.h>
#include <baselib.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>
#include <selinux_ss.h>

/* ---- policy view ------------------------------------------------------- */

#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */

/*
 * Field-for-field view of one policydb, filled from whichever of the two
 * layouts the kernel actually uses (probed, see kp_probe_pdb_layout).  Every
 * evaluator below reads the copy through this view only.
 */
struct kp_pdb_view
{
    int mls_enabled;
    struct symtab *symtab;
    struct flex_array **sym_val_to_name;
    struct class_datum **class_val_to_struct;
    struct role_datum **role_val_to_struct;
    struct flex_array *type_val_to_struct_array;
    struct avtab *te_avtab;
    struct avtab *te_cond_avtab;
    struct role_allow *role_allow;
    struct flex_array *type_attr_map_array;
    u16 process_class;
    u32 process_trans_perms;
    unsigned int n_classes;
    unsigned int n_types;
    unsigned int n_roles;
    unsigned int n_users;
    unsigned int n_levels;
    unsigned int n_cats;
};

static struct kp_pdb_view g_view;
static bool g_view_ready;
static bool g_android_layout;
static bool g_eval_ready;
static bool g_warned_once[4];

/* ---- resolved kernel helpers ------------------------------------------ */

typedef struct avtab_node *(*avtab_search_node_fn)(struct avtab *h, struct avtab_key *key);
typedef struct avtab_node *(*avtab_search_node_next_fn)(struct avtab_node *node, int specified);
typedef void (*cond_compute_av_fn)(struct avtab *ctab, struct avtab_key *key,
                                   struct av_decision *avd, struct extended_perms *xperms);
typedef int (*ebitmap_get_bit_fn)(struct ebitmap *e, unsigned long bit);
typedef int (*ebitmap_cmp_fn)(struct ebitmap *e1, struct ebitmap *e2);
typedef int (*ebitmap_contains_fn)(struct ebitmap *e1, struct ebitmap *e2, u32 last_e2bit);
typedef void *(*flex_array_get_fn)(struct flex_array *fa, unsigned int element_nr);
typedef void *(*flex_array_get_ptr_fn)(struct flex_array *fa, unsigned int element_nr);

static avtab_search_node_fn kp_avtab_search_node;
static avtab_search_node_next_fn kp_avtab_search_node_next;
static cond_compute_av_fn kp_cond_compute_av;
static ebitmap_get_bit_fn kp_ebitmap_get_bit;
static ebitmap_cmp_fn kp_ebitmap_cmp;
static ebitmap_contains_fn kp_ebitmap_contains;
static flex_array_get_fn kp_flex_array_get;
static flex_array_get_ptr_fn kp_flex_array_get_ptr;

static int kp_resolve_eval_symbols(void)
{
    kp_avtab_search_node = (avtab_search_node_fn)lookup_name_with_suffix("avtab_search_node");
    kp_avtab_search_node_next =
        (avtab_search_node_next_fn)lookup_name_with_suffix("avtab_search_node_next");
    kp_cond_compute_av = (cond_compute_av_fn)lookup_name_with_suffix("cond_compute_av");
    kp_ebitmap_get_bit = (ebitmap_get_bit_fn)lookup_name_with_suffix("ebitmap_get_bit");
    kp_ebitmap_cmp = (ebitmap_cmp_fn)lookup_name_with_suffix("ebitmap_cmp");
    kp_ebitmap_contains = (ebitmap_contains_fn)lookup_name_with_suffix("ebitmap_contains");
    kp_flex_array_get = (flex_array_get_fn)lookup_name_with_suffix("flex_array_get");
    kp_flex_array_get_ptr = (flex_array_get_ptr_fn)lookup_name_with_suffix("flex_array_get_ptr");

    if (!kp_avtab_search_node || !kp_avtab_search_node_next || !kp_cond_compute_av ||
        !kp_ebitmap_get_bit || !kp_ebitmap_cmp || !kp_ebitmap_contains ||
        !kp_flex_array_get || !kp_flex_array_get_ptr) {
        logkfw("selinux_hide: legacy: policy evaluator symbols missing "
               "(avtab %d/%d/%d ebitmap %d/%d/%d flex_array %d/%d)\n",
               !!kp_avtab_search_node, !!kp_avtab_search_node_next, !!kp_cond_compute_av,
               !!kp_ebitmap_get_bit, !!kp_ebitmap_cmp, !!kp_ebitmap_contains,
               !!kp_flex_array_get, !!kp_flex_array_get_ptr);
        return -ENOENT;
    }
    return 0;
}

/* ---- layout probe ------------------------------------------------------ */

/* Kernel pointers on arm64 start with 0xff in the top byte for both 39- and
 * 48-bit VA layouts; user-space values (the android_netlink_* ints) do not. */
static bool kp_looks_like_kernel_ptr(unsigned long p)
{
    return p != 0 && (p >> 56) == 0xff;
}

/* symtab[] stride is 16 bytes on 64-bit (pointer + u32 nprim + padding). */
#define KP_SYMTAB_STRIDE 16

static u32 kp_pdb_u32(void *base, unsigned int off)
{
    u32 v = 0;

    lib_memcpy(&v, (char *)base + off, sizeof(v));
    return v;
}

static unsigned long kp_pdb_ptr(void *base, unsigned int off)
{
    unsigned long v = 0;

    lib_memcpy(&v, (char *)base + off, sizeof(v));
    return v;
}

/* A layout is plausible when the first four symbol tables are hashtab pointers
 * and the class/type counts are non-zero and sane.  The commons table may be
 * empty (a policy with no common permissions), so its count is not checked. */
static bool kp_layout_sane(void *pdb, unsigned int base)
{
    unsigned int i;
    u32 classes, types;

    for (i = 0; i < 4; i++) {
        if (!kp_looks_like_kernel_ptr(kp_pdb_ptr(pdb, base + KP_SYMTAB_STRIDE * i))) return false;
    }
    classes = kp_pdb_u32(pdb, base + KP_SYMTAB_STRIDE * SYM_CLASSES + 8);
    types = kp_pdb_u32(pdb, base + KP_SYMTAB_STRIDE * SYM_TYPES + 8);
    return classes > 0 && classes <= 4096 && types > 0 && types <= 100000;
}

/*
 * Android trees carry two extra ints (android_netlink_route/getneigh) right
 * after mls_enabled, upstream does not.  Both layouts pad the first member to
 * 8 bytes for symtab[0].table, so symtab[] starts at +8 (plain) or +16
 * (Android).  The layout cannot be assumed from the kernel version -- it is
 * read back from the copy we just built.
 *
 * Returns 0 for the plain layout, 1 for the Android one, -1 when neither fits.
 */
static int kp_probe_pdb_layout(void *pdb)
{
    if (kp_layout_sane(pdb, 8)) return 0;
    if (kp_layout_sane(pdb, 16)) return 1;
    return -1;
}

#define KP_FILL_VIEW(p)                                                                    \
    do {                                                                                   \
        g_view.mls_enabled = (p)->mls_enabled;                                             \
        g_view.symtab = (p)->symtab;                                                       \
        g_view.sym_val_to_name = (struct flex_array **)(p)->sym_val_to_name;               \
        g_view.class_val_to_struct = (p)->class_val_to_struct;                             \
        g_view.role_val_to_struct = (p)->role_val_to_struct;                               \
        g_view.type_val_to_struct_array = (p)->type_val_to_struct_array;                    \
        g_view.te_avtab = &(p)->te_avtab;                                                  \
        g_view.te_cond_avtab = &(p)->te_cond_avtab;                                        \
        g_view.role_allow = (p)->role_allow;                                               \
    } while (0)

static bool kp_view_sane(void)
{
    bool ok = g_view.symtab && g_view.sym_val_to_name && g_view.class_val_to_struct &&
              g_view.role_val_to_struct && g_view.type_attr_map_array && g_view.te_avtab &&
              g_view.n_classes && g_view.n_classes <= 4096 && g_view.n_types &&
              g_view.n_types <= 100000 && g_view.n_users && g_view.n_roles;

    if (!ok)
        logkfw("selinux_hide: legacy: view rejected: symtab %llx val_to_name %llx class %llx "
               "role %llx attr_map %llx avtab %llx classes %u types %u users %u roles %u\n",
               (unsigned long long)(unsigned long)g_view.symtab,
               (unsigned long long)(unsigned long)g_view.sym_val_to_name,
               (unsigned long long)(unsigned long)g_view.class_val_to_struct,
               (unsigned long long)(unsigned long)g_view.role_val_to_struct,
               (unsigned long long)(unsigned long)g_view.type_attr_map_array,
               (unsigned long long)(unsigned long)g_view.te_avtab, g_view.n_classes, g_view.n_types,
               g_view.n_users, g_view.n_roles);
    return ok;
}

/*
 * Everything after role_allow depends on OCON_NUM, the number of slots in
 * ocontexts[]: 7 in 4.9 and 4.10, 9 from 4.11 on (Infiniband pkeys and end
 * ports).  Each extra slot pushes type_attr_map_array, policycaps,
 * permissive_map, len, policyvers, process_class and process_trans_perms eight
 * bytes further, so no single struct layout can serve every kernel.  The slot
 * count is probed instead, with the policydb's own process_class field as the
 * witness: it has to name the class "process".
 *
 * Offsets below are from the start of the struct; 0x150 is ocontexts[] when
 * symtab[] starts at +8, and the android layout moves everything by +8.
 */
#define KP_OCONTEXTS_OFF 0x150u

static const char *kp_policy_name(unsigned int sym, unsigned int idx);

static int kp_fill_tail(void *pdb, unsigned int base, unsigned int process_class)
{
    static const unsigned char slots[] = {5, 7, 9, 11};
    unsigned int i;

    for (i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
        unsigned int t = KP_OCONTEXTS_OFF + (base - 8u) + 8u * slots[i];
        unsigned long attr = kp_pdb_ptr(pdb, t + 16);
        unsigned long caps = kp_pdb_ptr(pdb, t + 24);
        unsigned long perm = kp_pdb_ptr(pdb, t + 40);
        u32 vers = kp_pdb_u32(pdb, t + 64);
        u32 cls = kp_pdb_u32(pdb, t + 70) & 0xffffu;

        if (!kp_looks_like_kernel_ptr(attr)) continue;
        if (caps && !kp_looks_like_kernel_ptr(caps)) continue;
        if (perm && !kp_looks_like_kernel_ptr(perm)) continue;
        if (vers < 15 || vers > 45) continue;
        if (cls != process_class) continue;

        g_view.type_attr_map_array = (struct flex_array *)attr;
        g_view.process_class = (u16)process_class;
        g_view.process_trans_perms = kp_pdb_u32(pdb, t + 72);
        log_boot("selinux_hide: legacy: tail layout with %u ocontext slots (policyvers %u)\n",
                 slots[i], vers);
        return 0;
    }
    return -EINVAL;
}

static int kp_fill_view(void *pdb)
{
    int layout = kp_probe_pdb_layout(pdb);
    unsigned int base, i, process_class = 0;

    if (layout < 0) {
        logkfw("selinux_hide: legacy: policydb layout not recognised, no evaluation\n");
        return -EINVAL;
    }
    g_android_layout = layout == 1;
    base = g_android_layout ? 16u : 8u;

    lib_memset(&g_view, 0, sizeof(g_view));
    if (g_android_layout)
        KP_FILL_VIEW((struct policydb *)pdb);
    else
        KP_FILL_VIEW((struct policydb_plain *)pdb);

    g_view.n_classes = g_view.symtab[SYM_CLASSES].nprim;
    g_view.n_types = g_view.symtab[SYM_TYPES].nprim;
    g_view.n_roles = g_view.symtab[SYM_ROLES].nprim;
    g_view.n_users = g_view.symtab[SYM_USERS].nprim;
    g_view.n_levels = g_view.symtab[SYM_LEVELS].nprim;
    g_view.n_cats = g_view.symtab[SYM_CATS].nprim;

    /* Last cheap sanity check before anything walks the copy: a mis-probed
     * layout shows up here as a nonsense mls_enabled, and evaluating an
     * "MLS" policy that is not one walks garbage range structures. */
    if (g_view.mls_enabled != 0 && g_view.mls_enabled != 1) {
        logkfw("selinux_hide: legacy: policydb mls_enabled looks wrong (%d), no evaluation\n",
               g_view.mls_enabled);
        return -EINVAL;
    }

    for (i = 1; i <= g_view.n_classes && i <= 4096; i++) {
        const char *nm = kp_policy_name(SYM_CLASSES, i - 1);

        if (nm && !lib_strcmp(nm, "process")) {
            process_class = i;
            break;
        }
    }
    if (!process_class) {
        logkfw("selinux_hide: legacy: policy has no process class, no evaluation\n");
        return -EINVAL;
    }
    if (kp_fill_tail(pdb, base, process_class)) {
        logkfw("selinux_hide: legacy: policydb tail not recognised for class %u\n",
               process_class);
        return -EINVAL;
    }

    if (!kp_view_sane()) return -EINVAL;

    g_view_ready = true;
    log_boot("selinux_hide: legacy: policydb view ready (%s layout, mls %d, classes %u, types %u, "
             "levels %u, cats %u, process class %u)\n",
             g_android_layout ? "android" : "upstream", g_view.mls_enabled, g_view.n_classes,
             g_view.n_types, g_view.n_levels, g_view.n_cats, g_view.process_class);
    return 0;
}

/* ---- ebitmap traversal ------------------------------------------------- */

/* The kernel's ebitmap_for_each_positive_bit() is a macro over a node list;
 * this is the same walk written out, since the macro itself is not a symbol. */
#define KP_EBITMAP_UNIT_NUMS ((64 - sizeof(void *) - sizeof(u32)) / sizeof(unsigned long))
#define KP_EBITMAP_UNIT_BITS (KP_EBITMAP_UNIT_NUMS * 64)

/*
 * Next set bit at or after *bit.  *node is the iterator's cursor: the node that
 * covered the previous hit, so consecutive calls do not rescan from the head.
 *
 * Every walk is bounded and must move forward: with a mis-probed policydb the
 * node chain is garbage, and an unbounded walk there is an un-preemptible loop
 * inside the kernel (the caller's for-loop simply never ends).
 */
#define KP_EBIT_MAX_NODES 4096

static int kp_ebit_iter(struct ebitmap *e, struct ebitmap_node **node, unsigned int *bit)
{
    struct ebitmap_node *n = *node;
    unsigned int start = *bit;
    unsigned int b = start;
    int hops = 0;

    if (!e || !e->node || b >= e->highbit) return 0;

    if (!n || b < n->startbit || b >= n->startbit + KP_EBITMAP_UNIT_BITS) {
        n = e->node;
        while (n && n->startbit + KP_EBITMAP_UNIT_BITS <= b && hops++ < KP_EBIT_MAX_NODES)
            n = n->next;
    }

    while (n && hops++ < KP_EBIT_MAX_NODES) {
        unsigned int i;

        if (b < n->startbit) b = n->startbit;
        for (i = b - n->startbit; i < KP_EBITMAP_UNIT_BITS; i++) {
            if (n->maps[i >> 6] & (1UL << (i & 63))) {
                unsigned int hit = n->startbit + i;

                /* Strictly forward, or the caller's for-loop repeats forever. */
                if (hit <= start) return 0;
                *node = n;
                *bit = hit;
                return 1;
            }
        }
        n = n->next;
        if (n) b = n->startbit;
    }
    return 0;
}

#define KP_EBIT_FOR_EACH(e, node, bit) \
    for ((node) = NULL, (bit) = 0; kp_ebit_iter((e), &(node), &(bit)); (bit)++)

/* ---- MLS / constraint helpers ------------------------------------------ */

static int kp_mls_level_eq(struct mls_level *l1, struct mls_level *l2)
{
    return l1->sens == l2->sens && kp_ebitmap_cmp(&l1->cat, &l2->cat);
}

static int kp_mls_level_dom(struct mls_level *l1, struct mls_level *l2)
{
    return l1->sens >= l2->sens && kp_ebitmap_contains(&l1->cat, &l2->cat, 0);
}

#define KP_CEXPR_NOT 1
#define KP_CEXPR_AND 2
#define KP_CEXPR_OR 3
#define KP_CEXPR_ATTR 4
#define KP_CEXPR_NAMES 5

#define KP_CEXPR_USER 1
#define KP_CEXPR_ROLE 2
#define KP_CEXPR_TYPE 4
#define KP_CEXPR_TARGET 8
#define KP_CEXPR_XTARGET 16
#define KP_CEXPR_L1L2 32
#define KP_CEXPR_L1H2 64
#define KP_CEXPR_H1L2 128
#define KP_CEXPR_H1H2 256
#define KP_CEXPR_L1H1 512
#define KP_CEXPR_L2H2 1024

#define KP_CEXPR_EQ 1
#define KP_CEXPR_NEQ 2
#define KP_CEXPR_DOM 3
#define KP_CEXPR_DOMBY 4
#define KP_CEXPR_INCOMP 5

#define KP_CEXPR_MAXDEPTH 5

/*
 * Port of constraint_expr_eval() (4.9 - 4.14, no policydb argument).  The only
 * change is where the policy comes from: g_view instead of the global.  A "BUG"
 * in the original is impossible here by construction (the expressions come from
 * policydb_read of the same policy), so a bad node evaluates to "denied".
 */
static int kp_constraint_expr_eval(struct context *scontext, struct context *tcontext,
                                   struct context *xcontext, struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[KP_CEXPR_MAXDEPTH];
    int sp = -1;
    int hops = 0;

    for (e = cexpr; e && hops++ < KP_EBIT_MAX_NODES; e = e->next) {
        switch (e->expr_type) {
        case KP_CEXPR_NOT:
            if (sp < 0) return 0;
            s[sp] = !s[sp];
            break;
        case KP_CEXPR_AND:
            if (sp < 1) return 0;
            sp--;
            s[sp] &= s[sp + 1];
            break;
        case KP_CEXPR_OR:
            if (sp < 1) return 0;
            sp--;
            s[sp] |= s[sp + 1];
            break;
        case KP_CEXPR_ATTR:
            if (sp == KP_CEXPR_MAXDEPTH - 1) return 0;
            switch (e->attr) {
            case KP_CEXPR_USER:
                val1 = scontext->user;
                val2 = tcontext->user;
                break;
            case KP_CEXPR_TYPE:
                val1 = scontext->type;
                val2 = tcontext->type;
                break;
            case KP_CEXPR_ROLE:
                val1 = scontext->role;
                val2 = tcontext->role;
                if (!val1 || !val2 || val1 > g_view.n_roles || val2 > g_view.n_roles) return 0;
                r1 = g_view.role_val_to_struct[val1 - 1];
                r2 = g_view.role_val_to_struct[val2 - 1];
                if (!r1 || !r2) return 0;
                switch (e->op) {
                case KP_CEXPR_DOM:
                    s[++sp] = kp_ebitmap_get_bit(&r1->dominates, val2 - 1);
                    continue;
                case KP_CEXPR_DOMBY:
                    s[++sp] = kp_ebitmap_get_bit(&r2->dominates, val1 - 1);
                    continue;
                case KP_CEXPR_INCOMP:
                    s[++sp] = (!kp_ebitmap_get_bit(&r1->dominates, val2 - 1) &&
                               !kp_ebitmap_get_bit(&r2->dominates, val1 - 1));
                    continue;
                default:
                    break;
                }
                break;
            case KP_CEXPR_L1L2:
                l1 = &scontext->range.level[0];
                l2 = &tcontext->range.level[0];
                goto mls_ops;
            case KP_CEXPR_L1H2:
                l1 = &scontext->range.level[0];
                l2 = &tcontext->range.level[1];
                goto mls_ops;
            case KP_CEXPR_H1L2:
                l1 = &scontext->range.level[1];
                l2 = &tcontext->range.level[0];
                goto mls_ops;
            case KP_CEXPR_H1H2:
                l1 = &scontext->range.level[1];
                l2 = &tcontext->range.level[1];
                goto mls_ops;
            case KP_CEXPR_L1H1:
                l1 = &scontext->range.level[0];
                l2 = &scontext->range.level[1];
                goto mls_ops;
            case KP_CEXPR_L2H2:
                l1 = &tcontext->range.level[0];
                l2 = &tcontext->range.level[1];
                goto mls_ops;
mls_ops:
                switch (e->op) {
                case KP_CEXPR_EQ:
                    s[++sp] = kp_mls_level_eq(l1, l2);
                    continue;
                case KP_CEXPR_NEQ:
                    s[++sp] = !kp_mls_level_eq(l1, l2);
                    continue;
                case KP_CEXPR_DOM:
                    s[++sp] = kp_mls_level_dom(l1, l2);
                    continue;
                case KP_CEXPR_DOMBY:
                    s[++sp] = kp_mls_level_dom(l2, l1);
                    continue;
                case KP_CEXPR_INCOMP:
                    s[++sp] = !kp_mls_level_dom(l1, l2) && !kp_mls_level_dom(l2, l1);
                    continue;
                default:
                    return 0;
                }
            default:
                return 0;
            }

            switch (e->op) {
            case KP_CEXPR_EQ:
                s[++sp] = (val1 == val2);
                break;
            case KP_CEXPR_NEQ:
                s[++sp] = (val1 != val2);
                break;
            default:
                return 0;
            }
            break;
        case KP_CEXPR_NAMES:
            if (sp == KP_CEXPR_MAXDEPTH - 1) return 0;
            c = scontext;
            if (e->attr & KP_CEXPR_TARGET)
                c = tcontext;
            else if (e->attr & KP_CEXPR_XTARGET) {
                c = xcontext;
                if (!c) return 0;
            }
            if (e->attr & KP_CEXPR_USER)
                val1 = c->user;
            else if (e->attr & KP_CEXPR_ROLE)
                val1 = c->role;
            else if (e->attr & KP_CEXPR_TYPE)
                val1 = c->type;
            else
                return 0;
            if (!val1) return 0;

            switch (e->op) {
            case KP_CEXPR_EQ:
                s[++sp] = kp_ebitmap_get_bit(&e->names, val1 - 1);
                break;
            case KP_CEXPR_NEQ:
                s[++sp] = !kp_ebitmap_get_bit(&e->names, val1 - 1);
                break;
            default:
                return 0;
            }
            break;
        default:
            return 0;
        }
    }

    if (sp != 0) return 0;
    return s[0];
}

/* ---- decision ---------------------------------------------------------- */

/* Port of type_attribute_bounds_av().  The audit record the original emits is
 * skipped: it names types through the global policydb, and the decision itself
 * (masking the permissions that exceed the bound) is what callers see. */
static void kp_type_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass,
                              struct av_decision *avd);

static void kp_compute_av_in_policy(struct context *scontext, struct context *tcontext, u16 tclass,
                                    struct av_decision *avd)
{
    struct class_datum *tclass_datum;
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;
    int hops = 0;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;

    if (unlikely(!tclass || tclass > g_view.n_classes)) return;
    if (!g_view.class_val_to_struct) return;
    tclass_datum = g_view.class_val_to_struct[tclass - 1];
    if (!tclass_datum) return;

    if (!scontext->type || scontext->type > g_view.n_types) return;
    if (!tcontext->type || tcontext->type > g_view.n_types) return;

    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;

    sattr = kp_flex_array_get(g_view.type_attr_map_array, scontext->type - 1);
    tattr = kp_flex_array_get(g_view.type_attr_map_array, tcontext->type - 1);
    if (!sattr || !tattr) {
        if (!g_warned_once[0]) {
            g_warned_once[0] = true;
            logkfw("selinux_hide: legacy: no attribute map for types %u/%u, decision left empty\n",
                   scontext->type, tcontext->type);
        }
        return;
    }

    KP_EBIT_FOR_EACH(sattr, snode, i) {
        KP_EBIT_FOR_EACH(tattr, tnode, j) {
            avkey.source_type = (u16)(i + 1);
            avkey.target_type = (u16)(j + 1);
            for (node = kp_avtab_search_node(g_view.te_avtab, &avkey); node;
                 node = kp_avtab_search_node_next(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED)
                    avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW)
                    avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY)
                    avd->auditdeny &= node->datum.u.data;
                /* xperms are not requested here: selinuxfs' access query passes
                 * NULL for them, exactly like security_compute_av_user(). */
            }

            /* Conditional av table: the table pointer is explicit, so the real
             * kernel walker is used. */
            kp_cond_compute_av(g_view.te_cond_avtab, &avkey, avd, NULL);
        }
    }

    /* Constraints, including MLS. */
    constraint = tclass_datum->constraints;
    while (constraint && hops++ < KP_EBIT_MAX_NODES) {
        if ((constraint->permissions & avd->allowed) &&
            !kp_constraint_expr_eval(scontext, tcontext, NULL, constraint->expr))
            avd->allowed &= ~constraint->permissions;
        constraint = constraint->next;
    }

    /* Role change on a transition. */
    if (tclass == g_view.process_class && (avd->allowed & g_view.process_trans_perms) &&
        scontext->role != tcontext->role) {
        for (ra = g_view.role_allow; ra && hops++ < KP_EBIT_MAX_NODES; ra = ra->next) {
            if (scontext->role == ra->role && tcontext->role == ra->new_role) break;
        }
        if (!ra) avd->allowed &= ~g_view.process_trans_perms;
    }

    kp_type_bounds_av(scontext, tcontext, tclass, avd);
}

static void kp_type_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass,
                              struct av_decision *avd)
{
    struct context lo_scontext;
    struct context lo_tcontext, *tcontextp = tcontext;
    struct av_decision lo_avd;
    struct type_datum *source;
    struct type_datum *target;
    u32 masked;

    source = kp_flex_array_get_ptr(g_view.type_val_to_struct_array, scontext->type - 1);
    if (!source) return;
    if (!source->bounds) return;

    target = kp_flex_array_get_ptr(g_view.type_val_to_struct_array, tcontext->type - 1);
    if (!target) return;

    lib_memset(&lo_avd, 0, sizeof(lo_avd));
    lib_memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
    lo_scontext.type = source->bounds;

    if (target->bounds) {
        lib_memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;
        tcontextp = &lo_tcontext;
    }

    kp_compute_av_in_policy(&lo_scontext, tcontextp, tclass, &lo_avd);

    masked = ~lo_avd.allowed & avd->allowed;
    if (!masked) return;
    avd->allowed &= ~masked;
}

/* ---- context rendering ------------------------------------------------- */

/*
 * Port of context_struct_to_string() + mls_sid_to_context().  Same output, same
 * aliasing rules, but names come from the copy: the kernel's version renders
 * through the global policydb, which after a policy reload no longer describes
 * the copy's type/user/role ids.
 */

struct kp_strbuf
{
    char *p;
    unsigned long cap;
    unsigned long len;
    bool overflow;
};

static void kp_sb_putc(struct kp_strbuf *b, char c)
{
    if (b->len + 1 >= b->cap) {
        b->overflow = true;
        return;
    }
    b->p[b->len++] = c;
}

static void kp_sb_puts(struct kp_strbuf *b, const char *s)
{
    while (s && *s) kp_sb_putc(b, *s++);
}

static const char *kp_policy_name(unsigned int sym, unsigned int idx)
{
    char *name;

    if (!g_view.sym_val_to_name || sym >= SYM_NUM) return NULL;
    name = kp_flex_array_get_ptr(g_view.sym_val_to_name[sym], idx);
    if (!name || is_bad_address(name)) return NULL;
    return name;
}

static int kp_render_context(char *out, unsigned long cap, struct context *ctx)
{
    struct kp_strbuf b;
    const char *nm;
    int l;

    if (!out || cap < 8 || !ctx) return -EINVAL;

    /* Contexts the policy could not map keep their string verbatim. */
    if (ctx->len) {
        if (!ctx->str || ctx->len >= cap) return -ERANGE;
        lib_memcpy(out, ctx->str, ctx->len);
        out[ctx->len] = '\0';
        return 0;
    }

    if (!ctx->user || ctx->user > g_view.n_users) return -EINVAL;
    if (!ctx->role || ctx->role > g_view.n_roles) return -EINVAL;
    if (!ctx->type || ctx->type > g_view.n_types) return -EINVAL;

    lib_memset(&b, 0, sizeof(b));
    b.p = out;
    b.cap = cap;

    nm = kp_policy_name(SYM_USERS, ctx->user - 1);
    if (!nm) return -EINVAL;
    kp_sb_puts(&b, nm);
    kp_sb_putc(&b, ':');

    nm = kp_policy_name(SYM_ROLES, ctx->role - 1);
    if (!nm) return -EINVAL;
    kp_sb_puts(&b, nm);
    kp_sb_putc(&b, ':');

    nm = kp_policy_name(SYM_TYPES, ctx->type - 1);
    if (!nm) return -EINVAL;
    kp_sb_puts(&b, nm);

    if (g_view.mls_enabled) {
        kp_sb_putc(&b, ':');
        for (l = 0; l < 2; l++) {
            struct mls_level *lv = &ctx->range.level[l];
            struct ebitmap_node *node = NULL;
            unsigned int bit = 0;
            int head = -2, prev = -2;

            if (!lv->sens || lv->sens > g_view.n_levels) return -EINVAL;
            nm = kp_policy_name(SYM_LEVELS, lv->sens - 1);
            if (!nm) return -EINVAL;
            kp_sb_puts(&b, nm);

            KP_EBIT_FOR_EACH(&lv->cat, node, bit) {
                int cur = (int)bit;

                if (cur - prev > 1) {
                    /* one or more clear bits were skipped */
                    if (prev != head) {
                        if (prev - head > 1)
                            kp_sb_putc(&b, '.');
                        else
                            kp_sb_putc(&b, ',');
                        nm = prev >= 0 ? kp_policy_name(SYM_CATS, (unsigned int)prev) : NULL;
                        if (!nm) return -EINVAL;
                        kp_sb_puts(&b, nm);
                    }
                    kp_sb_putc(&b, prev < 0 ? ':' : ',');
                    nm = kp_policy_name(SYM_CATS, bit);
                    if (!nm) return -EINVAL;
                    kp_sb_puts(&b, nm);
                    head = cur;
                }
                prev = cur;
            }

            if (prev != head) {
                if (prev - head > 1)
                    kp_sb_putc(&b, '.');
                else
                    kp_sb_putc(&b, ',');
                nm = prev >= 0 ? kp_policy_name(SYM_CATS, (unsigned int)prev) : NULL;
                if (!nm) return -EINVAL;
                kp_sb_puts(&b, nm);
            }

            if (l == 0) {
                if (kp_mls_level_eq(&ctx->range.level[0], &ctx->range.level[1])) break;
                kp_sb_putc(&b, '-');
            }
        }
    }

    if (b.overflow) return -ERANGE;
    b.p[b.len] = '\0';
    return 0;
}

/* ---- registered evaluators -------------------------------------------- */

#define KP_RENDER_CAP 512

static void kp_legacy_av_impl(void *pdb, struct context *scontext, struct context *tcontext,
                              u16 tclass, struct av_decision *avd)
{
    (void)pdb;
    if (!avd) return;
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = KP_AVD_CLEAN_SEQNO;
    avd->flags = 0;
    if (!g_eval_ready || !scontext || !tcontext) return;
    kp_compute_av_in_policy(scontext, tcontext, tclass, avd);
}

static int kp_legacy_to_string_impl(void *pdb, struct context *ctx, char **out, u32 *out_len)
{
    char *buf;
    int rc;

    (void)pdb;
    if (!out || !out_len) return -EINVAL;
    *out = NULL;
    *out_len = 0;
    if (!g_eval_ready) return -ENOSYS;

    buf = selinux_sepolicy_kmalloc(KP_RENDER_CAP);
    if (!buf) return -ENOMEM;
    rc = kp_render_context(buf, KP_RENDER_CAP, ctx);
    if (rc) {
        kp_kernel_str_free(buf);
        return rc;
    }
    *out = buf;
    /* context_struct_to_string reports the length including the terminator, and
     * sel_write_context hands that value straight back to userspace, so the
     * length has to match the stock renderer byte for byte. */
    *out_len = (u32)lib_strlen(buf) + 1;
    return 0;
}

/* ---- self test --------------------------------------------------------- */

extern int security_context_to_sid_fn(const char *context, int len, u32 *sid, gfp_t gfp);

typedef void (*compute_av_user_plain_fn)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);
typedef void (*compute_av_user_state_fn)(void *state, u32 ssid, u32 tsid, u16 tclass,
                                        struct av_decision *avd);

#define KP_SELFTEST_MAX 12
#define KP_SELFTEST_INITIAL_SIDS 16
/* Sampled, not exhaustive: a broke port diverges on the first few classes, and
 * the full sweep (12 x 12 x every class, each one a live compute_av_user() on
 * top of our own evaluation) ran for seconds inside the post-fs-data event. */
#define KP_SELFTEST_MAX_CLASSES 8
#define KP_SELFTEST_MAX_DECISIONS 384

/*
 * No table of pointers may live in kpimg: the image is copied to a runtime base
 * without applying relocations, so every absolute pointer keeps its link-time
 * value and dereferencing it faults.  That rules out `static const char *x[]`
 * and, less obviously, `switch (...) { case N: return "literal"; }` as well -
 * GCC folds that into a CSWTCH table of string pointers.  The names therefore
 * live in one NUL-separated blob that is walked at runtime; the address of the
 * blob itself is materialised PC-relative and stays valid after the move.
 */
#define KP_KNOWN_CONTEXTS 8

static const char kp_known_blob[] =
    "u:r:init:s0\0"
    "u:r:kernel:s0\0"
    "u:r:zygote:s0\0"
    "u:r:untrusted_app:s0\0"
    "u:r:system_app:s0\0"
    "u:r:shell:s0\0"
    "u:r:su:s0\0"
    "u:r:priv_app:s0";

static const char *kp_known_context(int i)
{
    const char *p = kp_known_blob;
    int n;

    if (i < 0 || i >= KP_KNOWN_CONTEXTS) return NULL;
    for (n = 0; n < i; n++) p += lib_strlen(p) + 1;
    return p;
}

/*
 * Compare a sample of decisions against the kernel's own evaluation.
 *
 * Runs at post-fs-data "before", where the live policy IS the policy we copied,
 * so both sides must agree bit for bit; any difference means this backend's
 * port diverged and would answer queries wrongly.  Contexts are resolved in both
 * policies separately (their SIDs may differ), which also covers the copy's
 * parsers.
 *
 * The sample is policy-agnostic: the initial SIDs of the copy are rendered back
 * to context strings (which exercises the renderer) and used as both source and
 * target types, and the well-known Android domains are added when the policy has
 * them.  A mismatch is logged with its inputs; only the strict control file turns
 * it into a refusal, because a manager that reloaded the policy before this point
 * legitimately sees different answers.
 */
static unsigned int kp_selftest(void)
{
    static char rendered[KP_SELFTEST_INITIAL_SIDS][192];
    const char *probe[KP_SELFTEST_MAX];
    u32 clean_sid[KP_SELFTEST_MAX], live_sid[KP_SELFTEST_MAX];
    bool have[KP_SELFTEST_MAX];
    unsigned long av_addr, state_addr = 0;
    compute_av_user_plain_fn compute_plain = NULL;
    compute_av_user_state_fn compute_state = NULL;
    unsigned int classes, tclass, a, compared = 0, mismatched = 0, np = 0;
    unsigned int class_step;
    int i, sid;

    av_addr = lookup_name_with_suffix("security_compute_av_user");
    if (!av_addr) {
        logkfw("selinux_hide: legacy: selftest skipped, security_compute_av_user not found\n");
        return 0;
    }
    if (selinux_hide_ss_takes_state()) {
        state_addr = lookup_name_with_suffix("selinux_state");
        if (!state_addr) {
            logkfw("selinux_hide: legacy: selftest skipped, selinux_state not found\n");
            return 0;
        }
        compute_state = (compute_av_user_state_fn)av_addr;
    } else {
        compute_plain = (compute_av_user_plain_fn)av_addr;
    }

    /* Initial SIDs first: they are numbered identically in the copy and in the
     * live table, and rendering them is part of what the hooks do. */
    for (sid = 1; sid <= KP_SELFTEST_INITIAL_SIDS && np < 8; sid++) {
        struct context *ctx = selinux_sepolicy_sid_context((u32)sid);

        if (!ctx) continue;
        if (kp_render_context(rendered[np], sizeof(rendered[np]), ctx)) continue;
        probe[np] = rendered[np];
        np++;
    }
    for (i = 0; i < KP_KNOWN_CONTEXTS; i++) {
        const char *ctx = kp_known_context(i);

        if (!ctx || np >= KP_SELFTEST_MAX) break;
        probe[np++] = ctx;
    }

    for (i = 0; i < (int)np; i++) {
        u32 csid = 0, lsid = 0;

        have[i] = false;
        if (selinux_sepolicy_context_to_sid(probe[i], (u32)lib_strlen(probe[i]), &csid, KP_GFP_KERNEL))
            continue;
        if (security_context_to_sid_fn(probe[i], (int)lib_strlen(probe[i]), &lsid, KP_GFP_KERNEL))
            continue;
        clean_sid[i] = csid;
        live_sid[i] = lsid;
        have[i] = true;
    }

    classes = g_view.n_classes;
    if (classes > 128) classes = 128;
    class_step = (classes + KP_SELFTEST_MAX_CLASSES - 1) / KP_SELFTEST_MAX_CLASSES;
    if (!class_step) class_step = 1;

    for (i = 0; i < (int)np && compared < KP_SELFTEST_MAX_DECISIONS; i++) {
        if (!have[i]) continue;
        for (a = 0; a < np && compared < KP_SELFTEST_MAX_DECISIONS; a++) {
            if (!have[a]) continue;
            for (tclass = 1; tclass <= classes && compared < KP_SELFTEST_MAX_DECISIONS;
                 tclass += class_step) {
                struct av_decision ours, live;
                struct context *sctx, *tctx;

                sctx = selinux_sepolicy_sid_context(clean_sid[a]);
                tctx = selinux_sepolicy_sid_context(clean_sid[i]);
                if (!sctx || !tctx) continue;

                lib_memset(&ours, 0, sizeof(ours));
                lib_memset(&live, 0, sizeof(live));
                kp_compute_av_in_policy(sctx, tctx, (u16)tclass, &ours);
                if (compute_state)
                    compute_state((void *)state_addr, live_sid[a], live_sid[i], (u16)tclass, &live);
                else
                    compute_plain(live_sid[a], live_sid[i], (u16)tclass, &live);

                compared++;
                if (ours.allowed != live.allowed || ours.auditallow != live.auditallow ||
                    ours.auditdeny != live.auditdeny) {
                    mismatched++;
                    if (mismatched <= 8)
                        logkfw("selinux_hide: legacy: selftest mismatch %s -> %s class %u: "
                               "ours %x/%x/%x live %x/%x/%x\n",
                               probe[a], probe[i], tclass, ours.allowed, ours.auditallow,
                               ours.auditdeny, live.allowed, live.auditallow, live.auditdeny);
                }
            }
        }
    }

    logkfi("selinux_hide: legacy: selftest compared %u decisions over %u context(s) and %u of "
           "%u classes (step %u), %u mismatch(es)\n",
           compared, np, (classes + class_step - 1) / class_step, classes, class_step, mismatched);
    if (!compared)
        logkfw("selinux_hide: legacy: selftest could not compare anything (no probe context "
               "resolved in both policies)\n");
    return mismatched;
}

/* ---- feature entry points --------------------------------------------- */

#define KP_SELINUX_HIDE_STRICT_FILE "/data/adb/ap/selinux_hide_strict"

static bool g_legacy_enabled;

int selinux_hide_legacy_init(void)
{
    int rc;

    if (!selinux_hide_legacy_required()) return -EOPNOTSUPP;

    rc = kp_resolve_eval_symbols();
    if (rc) return rc;

    if (!selinux_sepolicy_backup_ready()) {
        rc = selinux_sepolicy_snapshot();
        log_boot("selinux_hide: legacy: snapshot rc=%d\n", rc);
        if (rc) return rc;
    }
    if (!selinux_sepolicy_backup_ready()) return -EAGAIN;

    rc = kp_fill_view(selinux_sepolicy_policydb());
    if (rc) return rc;

    selinux_sepolicy_register_legacy_impl(kp_legacy_av_impl, kp_legacy_to_string_impl);
    g_eval_ready = true;

    if (selinux_sepolicy_snapshot_dirty()) {
        struct file *sf = filp_open(KP_SELINUX_HIDE_STRICT_FILE, 0, 0);

        if (!IS_ERR(sf)) {
            filp_close(sf, 0);
            logkfw("selinux_hide: legacy: %s is present and the snapshot already carries a "
                   "manager domain, refusing to enable\n", KP_SELINUX_HIDE_STRICT_FILE);
            g_eval_ready = false;
            return -EPERM;
        }
        logkfw("selinux_hide: legacy: snapshot already carries a manager domain, hiding is "
               "ineffective (add %s to enforce)\n", KP_SELINUX_HIDE_STRICT_FILE);
    }

    if (kp_selftest()) {
        struct file *sf = filp_open(KP_SELINUX_HIDE_STRICT_FILE, 0, 0);

        if (!IS_ERR(sf)) {
            filp_close(sf, 0);
            logkfw("selinux_hide: legacy: selftest disagrees with the kernel and %s is present, "
                   "refusing to enable\n", KP_SELINUX_HIDE_STRICT_FILE);
            g_eval_ready = false;
            return -EINVAL;
        }
    }

    logkfi("selinux_hide: legacy backend ready (%s policydb, mls %d)\n",
           g_android_layout ? "android" : "upstream", g_view.mls_enabled);
    return 0;
}

int selinux_hide_legacy_enable(void)
{
    if (!g_eval_ready || !g_view_ready) {
        logkfw("selinux_hide: legacy: evaluator not ready, cannot enable\n");
        return -EAGAIN;
    }
    selinux_sepolicy_register_legacy_impl(kp_legacy_av_impl, kp_legacy_to_string_impl);
    g_legacy_enabled = true;
    return 0;
}

void selinux_hide_legacy_disable(void)
{
    selinux_sepolicy_register_legacy_impl(NULL, NULL);
    g_legacy_enabled = false;
}

int selinux_hide_legacy_is_enabled(void)
{
    return g_legacy_enabled;
}
