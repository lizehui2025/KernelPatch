/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * Deep copy of the clean SELinux policy, in the spirit of KernelSU's
 * ksu_dup_sepolicy()/backup_sepolicy: serialize the (still stock) live policy
 * with security_read_policy(), rebuild a fully independent policydb from the
 * blob with policydb_read(), restore the serialized length and load the initial
 * SIDs into our own sidtab.  policydb_read() rebuilds every inner table
 * (symtabs, val_to_struct maps, avtabs, hashtabs, ebitmaps, cond lists), so the
 * copy owns all of its pointers and needs no fixup loops -- unlike a shallow
 * struct copy, which would share them with the live policy.
 *
 * The copy is consumed through the ss/ wrappers below (policydb + sidtab passed
 * explicitly), so the same code serves every supported kernel; no fake
 * struct selinux_state is involved.
 *
 * AOSP Android config bits: policydb_write() (called inside
 * security_read_policy()) is hooked by patch/android/sepolicy_flags.c, which
 * ORs android_netlink_route/getneigh into the serialized config -- the same fix
 * KernelSU applies by patching the blob's config word at offset 20.
 *
 * NOTE: we deliberately do NOT use security_load_policy() for the copy -- it
 * starts an async sidtab-conversion workqueue that cannot be safely cancelled
 * and wedges the workqueue pool, freezing the system.
 */

#include <selinux_sepolicy.h>
#include <selinux_hide.h> /* lookup_name_with_suffix */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <predata.h>
#include <kputils.h>
#include <baselib.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm/cmpxchg.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>
#include <kbtf.h>
#include <selinux_hide.h>

#ifdef KP_SELINUX_HIDE_SELFTEST
void selinux_hide_selftest_on_policy_load(void);
#endif

/* ---- constants ---- */

#define KP_POLICY_POLICYDB_OFFSET (sizeof(void *)) /* struct selinux_policy { sidtab*, policydb, ... } */
/* Heap allocations for the copy (KernelSU uses kmemdup/vmalloc the same way).
 * Generous margins: kernel code writes the structs at its own compiled offsets
 * and the real structs may be larger than the layouts declared below. */
#define KP_BACKUP_POLICY_SIZE 0x8000 /* standalone policydb + wrapper */
#define KP_BACKUP_SIDTAB_SIZE 0x4000 /* struct sidtab (hash roots etc.) */
#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */
#define KP_CONTEXT_PAYLOAD_LIMIT 4096

#include <selinux_ss.h>

/* ---- vmalloc with the GKI *_noprof fallback ---- */

void *kp_vmalloc(unsigned long size)
{
    if (kfunc(vmalloc)) return kfunc(vmalloc)(size);
    if (kfunc(vmalloc_noprof)) return kfunc(vmalloc_noprof)(size);
    return NULL;
}

void kp_vfree(const void *addr)
{
    if (kfunc(vfree)) kfunc(vfree)(addr);
}

typedef void *(*kp_kmalloc_fn)(size_t, gfp_t);
typedef void (*kp_kfree_fn)(const void *);

static kp_kmalloc_fn kp_payload_kmalloc;
static kp_kfree_fn kp_payload_kfree;
static bool kp_payload_resolved;

static void kp_payload_resolve(void)
{
    if (kp_payload_resolved) return;
    kp_payload_resolved = true;

    kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("__kmalloc");
    if (!kp_payload_kmalloc) kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("__kmalloc_noprof");
    if (!kp_payload_kmalloc) kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("kmalloc");
    kp_payload_kfree = (kp_kfree_fn)lookup_name_with_suffix("kfree");
    log_boot("selinux_sepolicy: payload allocator: %s, free: %s\n",
             kp_payload_kmalloc ? "kmalloc" : "vmalloc", kp_payload_kfree ? "kfree" : "none");
}

static void *kp_payload_alloc(size_t size, gfp_t gfp, bool *via_vmalloc)
{
    kp_payload_resolve();
    if (kp_payload_kmalloc && kp_payload_kfree) {
        *via_vmalloc = false;
        return kp_payload_kmalloc(size, gfp);
    }
    *via_vmalloc = true;
    return kp_vmalloc(size);
}

static void kp_payload_free(void *p, bool via_vmalloc)
{
    if (!p) return;
    if (via_vmalloc) kp_vfree(p);
    else if (kp_payload_kfree) kp_payload_kfree(p);
}

void kp_kernel_str_free(void *p)
{
    static bool warned;

    if (!p) return;
    kp_payload_resolve();
    if (kp_payload_kfree) {
        kp_payload_kfree(p);
        return;
    }
    if (!warned) {
        warned = true;
        logkfw("selinux_sepolicy: kfree unresolved, kernel strings cannot be released\n");
    }
}

/* ---- resolved symbols ---- */

typedef int (*policydb_read_fn)(struct policydb *p, struct policy_file *fp);
typedef int (*policydb_load_isids_fn)(struct policydb *p, void *s);
typedef void (*policydb_destroy_fn)(struct policydb *p);
static policydb_read_fn kp_policydb_read;
static policydb_load_isids_fn kp_policydb_load_isids;
static policydb_destroy_fn kp_policydb_destroy;

/* Destroying the local struct context after sidtab_context_to_sid() is what the
 * stock security_context_to_sid_core() does: the parser allocates one ebitmap
 * node per MLS level (range.level[0/1].cat) and the sidtab keeps its own copy.
 * context_destroy() itself is a static inline in 4.9 - 6.14 (single argument,
 * no policydb), so there is no unambiguous symbol to call -- and this kernel
 * carries two out-of-line copies of it.  Use the one global helper it calls
 * instead; ebitmap_destroy() is exported in every version and is NULL-safe. */
typedef void (*ebitmap_destroy_fn)(struct ebitmap *e);
static ebitmap_destroy_fn kp_ebitmap_destroy;

static void kp_context_destroy(struct context *c)
{
    if (!c) return;
    if (kp_ebitmap_destroy) {
        kp_ebitmap_destroy(&c->range.level[0].cat);
        kp_ebitmap_destroy(&c->range.level[1].cat);
    }
    /* Only set on the force/def_sid path, which the query wrappers never take. */
    if (c->str) kp_kernel_str_free(c->str);
    lib_memset(c, 0, sizeof(*c));
}

/* ss/ internals used by the *_with_policy wrappers. */
typedef int (*string_to_context_struct_fn)(struct policydb *pol, void *sidtab, char *scontext,
                                           struct context *ctx, u32 def_sid);
/* 4.14/4.19 pass the explicit context length, 5.0 dropped it -- the same
 * boundary as selinux_hide_is_new_version(). */
typedef int (*string_to_context_struct_6_fn)(struct policydb *pol, void *sidtab, char *scontext,
                                             u32 scontext_len, struct context *ctx, u32 def_sid);
typedef int (*sidtab_context_to_sid_fn)(void *s, struct context *context, u32 *out_sid);
typedef struct sidtab_entry *(*sidtab_search_entry_fn)(void *s, u32 sid);
/* 4.9 - 5.9 return the context directly; 5.10+ replaced this with
 * sidtab_search_entry(). */
typedef struct context *(*sidtab_search_fn)(void *s, u32 sid);
typedef int (*sidtab_sid2str_get_fn)(void *s, struct sidtab_entry *entry, char **out, u32 *out_len);
typedef void (*sidtab_sid2str_put_fn)(void *s, struct sidtab_entry *entry, char *str, u32 str_len);
typedef int (*context_struct_to_string_fn)(struct policydb *p, struct context *context, char **scontext,
                                           u32 *scontext_len);
/* 4.9 / 4.14 (pre-selinux_state) take no policydb: the helper resolves symbols
 * through the global policy database. */
typedef int (*context_struct_to_string_3_fn)(struct context *context, char **scontext, u32 *scontext_len);
typedef struct sidtab_entry *(*sidtab_search_core_fn)(void *s, u32 sid, int force);
typedef void (*context_struct_compute_av_fn)(struct policydb *policydb, struct context *scontext,
                                             struct context *tcontext, u16 tclass, struct av_decision *avd,
                                             struct extended_perms *xperms);

static string_to_context_struct_fn kp_string_to_context_struct;
static string_to_context_struct_6_fn kp_string_to_context_struct_6;
static sidtab_context_to_sid_fn kp_sidtab_context_to_sid;
static sidtab_search_entry_fn kp_sidtab_search_entry;
static sidtab_search_fn kp_sidtab_search;
static sidtab_sid2str_get_fn kp_sidtab_sid2str_get;
static sidtab_sid2str_put_fn kp_sidtab_sid2str_put;
static context_struct_to_string_fn kp_context_struct_to_string;
static context_struct_to_string_3_fn kp_context_struct_to_string_3;
static sidtab_search_core_fn kp_sidtab_search_core;
static context_struct_compute_av_fn kp_context_struct_compute_av;

/* ---- state ---- */

static bool g_backup_ready;
static void *g_backup_policy; /* our own struct selinux_policy-equivalent (heap) */
static bool g_backup_allow_unknown;

static bool selinux_sepolicy_supported(void)
{
    return selinux_hide_is_supported();
}

static struct policydb *kp_backup_policydb(void);
static void *kp_backup_sidtab(void);
int selinux_sepolicy_snapshot(void);
static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp);
static int kp_string_to_context_into(struct policydb *policydb, void *sidtab, const char *scontext,
                                     u32 scontext_len, gfp_t gfp, struct context *out);
static struct context *kp_sidtab_context(void *sidtab, u32 sid, struct sidtab_entry **out_entry);
static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len);
static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/*
 * The 4.9 - 4.18 backend brings its own evaluators.  On those kernels
 * context_struct_compute_av() and context_struct_to_string() bind the global
 * policydb instead of taking it as an argument (upstream 4.9/4.14), so they
 * cannot be pointed at the deep copy.  The legacy backend therefore computes
 * the decision and renders the context itself from the copy, and registers the
 * two entry points here; until it does, the query helpers stay -ENOSYS and the
 * feature refuses to enable.
 */
static void (*kp_legacy_compute_av)(void *pdb, struct context *scontext, struct context *tcontext,
                                    u16 tclass, struct av_decision *avd);
static int (*kp_legacy_to_string)(void *pdb, struct context *ctx, char **out, u32 *out_len);

void selinux_sepolicy_register_legacy_impl(void (*av)(void *, struct context *, struct context *, u16,
                                                      struct av_decision *),
                                           int (*to_string)(void *, struct context *, char **, u32 *))
{
    kp_legacy_compute_av = av;
    kp_legacy_to_string = to_string;
}

#define KP_CLEAN_EVAL_SLOTS 8

static struct {
    void *task;
    u32 depth;
} clean_eval_slots[KP_CLEAN_EVAL_SLOTS];

static bool kp_clean_eval_enter(void)
{
    int i;

    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) == current) {
            clean_eval_slots[i].depth++;
            return true;
        }
    }
    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (cmpxchg(&clean_eval_slots[i].task, NULL, current) == NULL) {
            clean_eval_slots[i].depth = 1;
            return true;
        }
    }
    return false;
}

static void kp_clean_eval_leave(void)
{
    int i;

    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) != current) continue;
        if (clean_eval_slots[i].depth > 1) {
            clean_eval_slots[i].depth--;
        } else {
            clean_eval_slots[i].depth = 0;
            __atomic_store_n(&clean_eval_slots[i].task, NULL, __ATOMIC_RELEASE);
        }
        return;
    }
}

static bool kp_clean_eval_active(void)
{
    int i;

    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) == current &&
            clean_eval_slots[i].depth)
            return true;
    }
    return false;
}

int selinux_sepolicy_clean_eval_enter(void)
{
    return kp_clean_eval_enter() ? 0 : -EAGAIN;
}

void selinux_sepolicy_clean_eval_leave(void)
{
    kp_clean_eval_leave();
}

static bool g_policydb_redirect_disabled;
static bool g_policydb_redirect_active;

bool selinux_sepolicy_redirect_active(void)
{
    return g_policydb_redirect_active && !g_policydb_redirect_disabled;
}
static bool g_policydb_redirect_mismatch_warned;

static void before_context_struct_compute_av(hook_fargs6_t *a, void *u)
{
    void *clean;

    /* A 4.14 tree can export selinux_state without backporting the policydb
     * argument to context_struct_compute_av(): there arg0 is scontext and arg3
     * is the avd pointer.  Swapping arg0 in that case would hand the kernel a
     * struct context where it expects a policydb, so detect the 5-argument form
     * on the first call and never touch arg0 again.  tclass is u16, so arg3
     * stays below 0x10000; any kernel pointer sets the high 32 bits. */
    if (a->arg3 >> 32) {
        if (!g_policydb_redirect_mismatch_warned) {
            g_policydb_redirect_mismatch_warned = true;
            logkfw("selinux_hide: context_struct_compute_av is 5-argument on this kernel "
                   "(kver %x), policydb redirect disabled\n", kver);
        }
        g_policydb_redirect_disabled = true;
        return;
    }
    if (g_policydb_redirect_disabled) return;

    if (!kp_clean_eval_active() || !g_backup_ready) return;
    clean = kp_backup_policydb();
    if (!is_bad_address(clean)) {
        if (selinux_hide_query_log_level() >= 2)
            logkfi("query redirect compute_av: policydb %llx -> %llx\n", a->arg0, (unsigned long)clean);
        a->arg0 = (uint64_t)clean;
    }
}

/* string_to_context_struct: 4.14/4.19 take
 * (policydb, sidtab, scontext, scontext_len, ctx, def_sid), 5.0+ dropped the
 * length argument.  Only arg0 (the policydb) is rewritten, so capturing five
 * registers is enough on both forms. */
static void before_string_to_context_struct(hook_fargs5_t *a, void *u)
{
    if (kp_clean_eval_active() && g_backup_ready) {
        void *clean = kp_backup_policydb();
        if (!is_bad_address(clean)) {
            if (selinux_hide_query_log_level() >= 2)
                logkfi("query redirect string_to_context_struct: policydb %llx -> %llx\n", a->arg0,
                       (unsigned long)clean);
            a->arg0 = (uint64_t)clean;
        }
    }
}

/* ---- KernelSU-style deep copy of the clean policy ----
 * Mirror of KernelSU's ksu_dup_sepolicy(): the copy is fully independent, so
 * every pointer it holds belongs to it (that is what makes it a deep copy --
 * a struct copy would share the live policy's tables).  Steps:
 *   1. security_read_policy() serializes the (still stock) live policy; the
 *      policydb_write() hook in patch/android/sepolicy_flags.c has already
 *      fixed the AOSP android_netlink_route/getneigh config bits in the blob
 *      (KernelSU patches the same word by hand at offset 20).
 *   2. policydb_read() rebuilds a standalone policydb from the blob into a
 *      zeroed heap block laid out as
 *      struct selinux_policy { struct sidtab *sidtab; struct policydb; ... }.
 *   3. the serialized length is restored (KernelSU forces policydb.len too:
 *      the reparse can compute a different value).
 *   4. policydb_load_isids() populates our own sidtab with the initial SIDs, so
 *      sid <-> context queries answer from the copy (KernelSU gives
 *      backup_sepolicy a fresh sidtab the same way).
 *
 * Unlike security_load_policy() this starts no sidtab-conversion workqueue and
 * never touches the live policy, so it cannot wedge a workqueue pool.
 */

/* Snapshot cleanliness probe: the serialized policy is scanned for
 * root-manager artifacts.  The "clean" copy must be the boot policy, so if
 * these names are already present the snapshot was taken after the manager
 * reloaded the policy -- the feature would then be hiding nothing. */
static int kp_blob_count(const unsigned char *blob, size_t len, const char *needle)
{
    size_t n = lib_strlen(needle);
    int count = 0;

    if (!n || len < n) return 0;
    for (size_t i = 0; i + n <= len && count < 999; i++) {
        if (blob[i] == (unsigned char)needle[0] && lib_memcmp(blob + i, needle, n) == 0) count++;
    }
    return count;
}

/* Names that only appear in a policy once a root manager patched it (the same
 * set the on-device detectors probe for).  Explicit calls on purpose: an array
 * of string pointers inside kpimg is not relocated at load time, so its entries
 * would still hold link addresses and dereferencing them oopses. */
static bool kp_blob_is_clean(const void *blob, size_t len)
{
    int n;

    n = kp_blob_count(blob, len, "magisk");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'magisk' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "ksu");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'ksu' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "apatch");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'apatch' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "supolicy");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'supolicy' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "lsposed");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'lsposed' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "droidspaces");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'droidspaces' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "xposed");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'xposed' x%d\n", n);
        return false;
    }
    return true;
}

typedef int (*security_read_policy_compat_fn)(void *state, void **data, size_t *len);

static security_read_policy_compat_fn kp_security_read_policy_compat;
static unsigned long kp_sepolicy_state_addr;
static bool kp_sepolicy_read_logged;

/* Whether the ss/ helpers take a struct selinux_state argument -- one rule,
 * shared with the 4.9 - 4.18 backend (see selinux_hide_ss_takes_state). */
static bool kp_selinux_state_arg_required(void)
{
    return selinux_hide_ss_takes_state();
}

static int kp_sepolicy_read(void **data, size_t *len)
{
    bool without_state = !kp_selinux_state_arg_required();

    if (!kfunc(security_read_policy)) {
        kfunc(security_read_policy) = (typeof(kfunc(security_read_policy)))lookup_name_with_suffix(
            "security_read_policy");
        if (!kfunc(security_read_policy)) return -ENOENT;
    }

    if (!kp_sepolicy_read_logged) {
        kp_sepolicy_read_logged = true;
        log_boot("selinux_sepolicy: security_read_policy: %s ABI (kver %x)\n",
                 without_state ? "plain 2-arg" : "state 3-arg", kver);
    }

    if (without_state) return kfunc(security_read_policy)(data, len);

    if (!kp_sepolicy_state_addr) kp_sepolicy_state_addr = lookup_name_with_suffix("selinux_state");
    if (!kp_sepolicy_state_addr) {
        logkfw("selinux_sepolicy: selinux_state not found, the policy cannot be serialized\n");
        return -ENOENT;
    }
    if (!kp_security_read_policy_compat)
        kp_security_read_policy_compat = (security_read_policy_compat_fn)(uintptr_t)kfunc(security_read_policy);
    return kp_security_read_policy_compat((void *)kp_sepolicy_state_addr, data, len);
}

/* Best effort serialization outside the load path (the post-fs-data snapshot).
 *
 * 6.6 and 6.12 document that security_read_policy() must be called with
 * selinux_state.policy_mutex held: the read walks state->policy, which a
 * manager's reload can replace right around post-fs-data (one device shows the
 * reload at 4.588s and the snapshot at 4.542s).  The offset comes from BTF and
 * the mutex helpers from kallsyms, so pre-BTF kernels simply keep the unlocked
 * read and log it once instead of failing the snapshot. */
typedef void (*kp_mutex_op_fn)(void *);

static kp_mutex_op_fn kp_policy_mutex_lock;
static kp_mutex_op_fn kp_policy_mutex_unlock;
static long kp_policy_mutex_off = -2;
static bool kp_policy_mutex_warned;

static void *kp_policy_mutex(void)
{
    unsigned long state;

    if (kp_policy_mutex_off == -2) {
        kp_policy_mutex_off = kp_btf_member_offset("selinux_state", "policy_mutex");
        kp_policy_mutex_lock = (kp_mutex_op_fn)lookup_name_with_suffix("mutex_lock");
        kp_policy_mutex_unlock = (kp_mutex_op_fn)lookup_name_with_suffix("mutex_unlock");
    }
    if (kp_policy_mutex_off < 0 || kp_policy_mutex_off > 512 || (kp_policy_mutex_off & 7)) return NULL;
    if (!kp_policy_mutex_lock || !kp_policy_mutex_unlock) return NULL;
    state = lookup_name_with_suffix("selinux_state");
    if (!state) return NULL;
    return (void *)(state + (unsigned long)kp_policy_mutex_off);
}

static int kp_sepolicy_read_locked(void **data, size_t *len)
{
    void *m;
    int rc;

    /* Only 6.6+ requires (and documents) the external policy_mutex: there
     * security_read_policy() only walks state->policy, so a concurrent reload is
     * only excluded by that mutex.  4.9 protects the read with policy_rwlock and
     * 4.19 - 6.5 with their own rwsem, so taking the mutex there would just add a
     * lock-order risk for nothing. */
    if (kver < KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION) return kp_sepolicy_read(data, len);

    m = kp_policy_mutex();
    if (!m) {
        if (!kp_policy_mutex_warned) {
            kp_policy_mutex_warned = true;
            logkfw("selinux_sepolicy: policy_mutex not resolvable, reading the live policy "
                   "unlocked\n");
        }
        return kp_sepolicy_read(data, len);
    }
    kp_policy_mutex_lock(m);
    rc = kp_sepolicy_read(data, len);
    kp_policy_mutex_unlock(m);
    return rc;
}

/* ---- policy-load capture ----
 *
 * Android loads the policy more than once: first-stage init loads the platform
 * policy, second-stage init the full one (vendor/odm included), and only then
 * do the root managers reload it with their patches.  Snapshotting at
 * post-fs-data can therefore copy an EARLIER epoch (e.g. the platform-only
 * policy, which lacks vendor types such as msd_daemon) -- an "oracle" detector
 * asks the policy about contexts the device must know, gets "unknown" and
 * concludes the policy was swapped.
 *
 * So instead of guessing a time, keep the last blob whose scan is clean and
 * stop replacing it once a marker-carrying load shows up: at boot that yields
 * the full platform policy, and the manager's later reload cannot overwrite it.
 */
static void *g_clean_blob;      /* last marker-free policy blob (as loaded) */
static size_t g_clean_blob_len;
static bool g_clean_locked;     /* a marker-carrying load was seen */

static void kp_log_blob_diag(const char *tag, const void *blob, size_t len);

#define KP_POLICYDB_MAGIC 0xf97cff8cU

static bool kp_blob_looks_valid(const void *blob, size_t len)
{
    u32 magic = 0;

    /* 512 is the floor: a hand-built policy for a test kernel can be ~2 KB, and
     * anything smaller cannot carry the header policydb_read wants anyway. */
    if (!blob || len < 512 || len > (16u << 20)) return false;
    lib_memcpy(&magic, blob, sizeof(magic));
    return magic == KP_POLICYDB_MAGIC;
}

static bool kp_blob_config_word(const void *blob, size_t len, u32 *config)
{
    u32 magic = 0, slen = 0;
    size_t off;

    if (!blob || !config || len < 32) return false;
    lib_memcpy(&magic, blob, sizeof(magic));
    if (magic != KP_POLICYDB_MAGIC) return false;
    lib_memcpy(&slen, (const char *)blob + 4, sizeof(slen));
    if (!slen || slen > 64) return false;
    off = 8 + (size_t)slen + sizeof(u32);
    if (off + sizeof(u32) > len) return false;
    lib_memcpy(config, (const char *)blob + off, sizeof(*config));
    return true;
}

static void kp_capture_policy_load(uint64_t ret)
{
    void *data = NULL;
    size_t len = 0;
    void *copy;
    int rc;

    if ((int)ret != 0 || g_clean_locked) return;

    /* Never read the hooked function's arguments: security_load_policy's ABI
     * differs across versions and LTO can fold it (on 6.12-android16 arg0 is
     * not the blob pointer, and dereferencing it oopsed).  Serialize whatever is
     * live now instead: this runs from the selinuxfs write handler's after-hook,
     * i.e. after the commit and after policy_mutex was released, so "live" is
     * exactly the policy that was just loaded. */
    rc = kp_sepolicy_read_locked(&data, &len);
    if (rc == -ENOENT) return;
    if (rc) {
        log_boot("selinux_sepolicy: policy read after load failed rc=%d, nothing captured\n", rc);
        return;
    }
    if (!data || !len) return;
    if (!kp_blob_looks_valid(data, len)) {
        logkfw("selinux_sepolicy: serialized policy rejected (len %zu), ignoring this load\n", len);
        if (kfunc(kvfree)) kfunc(kvfree)(data);
        return;
    }

    if (!kp_blob_is_clean(data, len)) {
        g_clean_locked = true;
        log_boot("selinux_sepolicy: loaded policy len %zu carries root markers, keeping the %zu byte clean blob\n",
                 len, g_clean_blob_len);
        kp_log_blob_diag("rejected", data, len);
    } else {
        copy = kp_vmalloc(len);
        if (copy) {
            lib_memcpy(copy, data, len);
            if (g_clean_blob) kp_vfree(g_clean_blob);
            g_clean_blob = copy;
            g_clean_blob_len = len;
            log_boot("selinux_sepolicy: captured clean policy blob from a load (len %zu)\n", len);
        }
    }
    if (kfunc(kvfree)) kfunc(kvfree)(data);
}

/* ---- live policy probe (diagnostic) ----
 *
 * Serializes whatever the live policy is right now and counts the same markers
 * the detectors look for, so dmesg answers "is this moment clean?" without
 * changing anything else: nothing is captured, cached or enabled here.
 *
 * Called at post-fs-data before/after, after every policy load and on the
 * first app-side query, so a boot log shows whether the boot policy was
 * already patched and when it went dirty.  Read-only with respect to the
 * feature: it allocates the serialized copy and frees it again.
 */
void selinux_sepolicy_probe_live(const char *tag)
{
    void *data = NULL;
    size_t len = 0;
    int rc, magisk, ksu, apatch, supolicy, lsposed, droidspaces, xposed;

    if (!selinux_sepolicy_supported()) return;

    rc = kp_sepolicy_read_locked(&data, &len);
    if (rc || !data || !len) {
        log_boot("selinux_hide: PROBE live[%s] read failed rc=%d\n", tag ? tag : "?", rc);
        if (data && kfunc(kvfree)) kfunc(kvfree)(data);
        return;
    }

    magisk = kp_blob_count(data, len, "magisk");
    ksu = kp_blob_count(data, len, "ksu");
    apatch = kp_blob_count(data, len, "apatch");
    supolicy = kp_blob_count(data, len, "supolicy");
    lsposed = kp_blob_count(data, len, "lsposed");
    droidspaces = kp_blob_count(data, len, "droidspaces");
    xposed = kp_blob_count(data, len, "xposed");

    log_boot("selinux_hide: PROBE live[%s] len=%zu clean=%d magisk=%d ksu=%d apatch=%d "
             "supolicy=%d lsposed=%d droidspaces=%d xposed=%d\n",
             tag ? tag : "?", len,
             (magisk | ksu | apatch | supolicy | lsposed | droidspaces | xposed) ? 0 : 1,
             magisk, ksu, apatch, supolicy, lsposed, droidspaces, xposed);

    if (kfunc(kvfree)) kfunc(kvfree)(data);
}

/* Build-time self test: a kpimg built with -DKP_SELINUX_HIDE_SELFTEST drives the
 * feature right after a policy is installed -- the same sequence a manager's
 * post-fs-data event runs on a device, at the moment the live policy is exactly
 * the one we snapshot.  Release builds compile this to nothing. */
static void kp_selftest_after_load(uint64_t ret)
{
#ifdef KP_SELINUX_HIDE_SELFTEST
    static bool ran;

    if ((int)ret || ran) return;
    ran = true;
    selinux_hide_selftest_on_policy_load();
#else
    (void)ret;
#endif
}

/* Runs after the selinuxfs write handler returned: by then
 * security_load_policy() has staged, selinux_policy_commit() has installed and
 * policy_mutex has been released, so this is the first point where the new
 * policy can be read without sitting in a critical section. */
static void after_sel_write_load(hook_fargs4_t *a, void *u)
{
    static int probed_live;

    if ((long)a->ret <= 0) return;
    kp_capture_policy_load(0);
    kp_selftest_after_load(0);
    /* Diagnostic: one probe per load shows exactly which load introduced the
     * markers.  Bounded so a manager that reloads in a loop cannot flood the
     * log. */
    if (probed_live < 6) {
        probed_live++;
        selinux_sepolicy_probe_live("load");
    }
}

/*
 * Policy capture hangs off the selinuxfs write handler, NOT off
 * security_load_policy.
 *
 *   sel_write_load()
 *       mutex_lock(&selinux_state.policy_mutex)
 *       security_load_policy(data, count, &load_state)   // 6.6+: stages only
 *       selinux_policy_commit(&load_state)               // 6.6+: installs
 *       mutex_unlock(&selinux_state.policy_mutex)
 *
 * An after-hook on security_load_policy therefore ran with policy_mutex held
 * and, on 6.6+, before the commit: the first load saw a NULL state->policy and
 * every later load re-read the PREVIOUS epoch, so 4.19+ never got the clean
 * blob the snapshot is supposed to answer from -- while the whole 2 MB
 * serialize/scan/copy happened inside the boot path's critical section.
 *
 * The after-hook on sel_write_load runs once the handler returns: commit done,
 * mutex released.  One serialization there is both correct and outside every
 * lock, and it covers 4.19 - 6.5 (security_load_policy installs it itself) and
 * 4.9 - 4.18 (security_read_policy takes policy_rwlock on its own) unchanged.
 */
#define KP_SELINUX_CAPTURE_ON_LOAD 1

static bool g_load_hook_installed;

/* Idempotent: called from the boot-time init and again after the ss/ symbols
 * resolved at post-fs-data. */
static void kp_install_load_hook(void)
{
    unsigned long addr;

    if (g_load_hook_installed || !selinux_sepolicy_supported()) return;
    if (!KP_SELINUX_CAPTURE_ON_LOAD) {
        g_load_hook_installed = true;
        log_boot("selinux_sepolicy: policy capture disabled\n");
        return;
    }
    /* sel_write_load() is the handler; sel_write() is its dispatcher and is
     * used as a fallback when LTO folded the static helper into it. */
    addr = lookup_name_with_suffix("sel_write_load");
    if (!addr) addr = lookup_name_with_suffix("sel_write");
    if (!addr) {
        g_load_hook_installed = true;
        logkfw("selinux_sepolicy: sel_write_load not found, the clean policy will not be "
               "captured\n");
        return;
    }
    hook_wrap4((void *)addr, NULL, after_sel_write_load, NULL);
    g_load_hook_installed = true;
    log_boot("selinux_sepolicy: hooked sel_write_load @ %llx (capture after commit)\n", addr);
}

/* Called as early as possible (before_rest_init): the policy is loaded by
 * userspace init shortly after, so the capture hook must already be in place. */
int selinux_sepolicy_boot_init(void)
{
    if (!selinux_sepolicy_supported()) {
        log_boot("selinux_sepolicy: built-in backend not used (kver %x, legacy %d)\n",
                 kver, selinux_hide_legacy_required());
        return -EOPNOTSUPP;
    }
    kp_install_load_hook();
    return 0;
}

static void kp_log_blob_diag(const char *tag, const void *blob, size_t len)
{
    u32 vers = len >= 20 ? *(u32 *)((const char *)blob + 16) : 0;

    log_boot("selinux_sepolicy: %s scan (len %zu, vers %u)\n", tag, len, vers);
    log_boot("selinux_sepolicy:   device names: msd_daemon=%d msd_app=%d app_zygote=%d dex2oat=%d adbroot=%d\n",
             kp_blob_count(blob, len, "msd_daemon"), kp_blob_count(blob, len, "msd_app"),
             kp_blob_count(blob, len, "app_zygote"), kp_blob_count(blob, len, "dex2oat"),
             kp_blob_count(blob, len, "adbroot"));
    log_boot("selinux_sepolicy:   root names: magisk=%d ksu=%d apatch=%d lsposed=%d xposed=%d droidspaces=%d\n",
             kp_blob_count(blob, len, "magisk"), kp_blob_count(blob, len, "ksu"),
             kp_blob_count(blob, len, "apatch"), kp_blob_count(blob, len, "lsposed"),
             kp_blob_count(blob, len, "xposed"), kp_blob_count(blob, len, "droidspaces"));
}

static bool g_snapshot_dirty;

static void kp_probe_one(const char *ctx, int *hits)
{
    u32 sid = 0;
    int rc = kp_context_to_sid_with_policy(ctx, lib_strlen(ctx), &sid, SECSID_NULL, KP_GFP_KERNEL);

    if (!rc) {
        (*hits)++;
        logkfw("selinux_sepolicy: snapshot resolves %s -> sid %u; it already carries a manager "
               "domain, hiding it is ineffective\n",
               ctx, sid);
    }
}

static void kp_probe_snapshot_domains(void)
{
    int hits = 0;

    if (!g_backup_ready) return;
    /* u:r:su:s0 is NOT a manager artifact: AOSP ships a su domain in the stock
     * policy and it resolves on a clean device, so probing it only produced a
     * false "already dirty" verdict on every real phone.  Only domains that
     * exist exclusively after a manager patched the policy count here. */
    kp_probe_one("u:r:ksu:s0", &hits);
    kp_probe_one("u:r:magisk:s0", &hits);
    kp_probe_one("u:r:lsposed:s0", &hits);
    if (hits)
        g_snapshot_dirty = true;
    else
        log_boot("selinux_sepolicy: snapshot answers no manager domain (clean)\n");
}

bool selinux_sepolicy_snapshot_dirty(void)
{
    return g_snapshot_dirty;
}

static int kp_dup_sepolicy(void)
{
    struct policy_file fp;
    struct policydb *pdb;
    void *data = NULL;
    void *pol = NULL;
    void *sidtab = NULL;
    size_t len = 0;
    bool owned = false;
    bool live_clean = false;
    int rc;

    if (!kfunc(security_read_policy) || !kp_policydb_read || !kp_policydb_load_isids) {
        log_boot("selinux_sepolicy: security_read_policy/policydb_read/policydb_load_isids not resolved\n");
        return -ENOENT;
    }

    if (g_clean_blob && g_clean_blob_len) {
        /* The load path captured the full platform policy before any manager
         * patched it: parse THAT, not whatever is live now. */
        data = g_clean_blob;
        len = g_clean_blob_len;
        log_boot("selinux_sepolicy: using the captured clean policy blob (%zu bytes)\n", len);
    } else {
        rc = kp_sepolicy_read_locked(&data, &len);
        if (rc || !data || !len) {
            log_boot("selinux_sepolicy: security_read_policy failed rc=%d\n", rc);
            if (data && kfunc(kvfree)) kfunc(kvfree)(data);
            return rc ? rc : -EINVAL;
        }
        if (!kp_blob_looks_valid(data, len)) {
            logkfw("selinux_sepolicy: serialized policy rejected (len %zu), no snapshot\n", len);
            if (kfunc(kvfree)) kfunc(kvfree)(data);
            return -EINVAL;
        }
        owned = true;
        /* No load was captured: this is whatever policy is live now, so report
         * whether it is still free of root markers. */
        live_clean = kp_blob_is_clean(data, len);
        log_boot("selinux_sepolicy: live blob scan (len %zu), clean=%d\n", len, live_clean);
    }

    /* The two blocks below are sized for the layouts this file declares.  BTF
     * can prove that a newer kernel's structs still fit; without BTF the
     * generous sizes stay the only guarantee, so the check is skipped rather
     * than failed. */
    {
        long need = kp_btf_type_size("policydb");

        if (need > 0 && (unsigned long)need + KP_POLICY_POLICYDB_OFFSET > KP_BACKUP_POLICY_SIZE) {
            logkfw("selinux_sepolicy: struct policydb needs %ld bytes, the policy block holds %lu\n",
                   need, (unsigned long)(KP_BACKUP_POLICY_SIZE - KP_POLICY_POLICYDB_OFFSET));
            rc = -E2BIG;
            goto out_free;
        }
        need = kp_btf_type_size("sidtab");
        if (need > 0 && (unsigned long)need > KP_BACKUP_SIDTAB_SIZE) {
            logkfw("selinux_sepolicy: struct sidtab needs %ld bytes, the sidtab block holds %u\n",
                   need, (unsigned)KP_BACKUP_SIDTAB_SIZE);
            rc = -E2BIG;
            goto out_free;
        }
    }

    /* policydb_read()/policydb_load_isids() require zero-initialized targets
     * with room for the real structs, which may be larger than the layouts we
     * declare below; hence the generous heap blocks. */
    pol = kp_vmalloc(KP_BACKUP_POLICY_SIZE);
    sidtab = kp_vmalloc(KP_BACKUP_SIDTAB_SIZE);
    if (!pol || !sidtab) {
        log_boot("selinux_sepolicy: copy allocation failed\n");
        rc = -ENOMEM;
        goto out_free;
    }
    lib_memset(pol, 0, KP_BACKUP_POLICY_SIZE);
    lib_memset(sidtab, 0, KP_BACKUP_SIDTAB_SIZE);

    pdb = (struct policydb *)((char *)pol + KP_POLICY_POLICYDB_OFFSET);
    fp.data = data;
    fp.len = len;
    rc = kp_policydb_read(pdb, &fp);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_read failed rc=%d\n", rc);
        goto out_free;
    }

    {
        u32 config = 0;

        if (kp_blob_config_word(data, len, &config))
            g_backup_allow_unknown = (config & 0x4) != 0;
        else
            logkfw("selinux_sepolicy: policy header unparsable, assuming deny_unknown\n");
    }

    rc = kp_policydb_load_isids(pdb, sidtab);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_load_isids failed rc=%d\n", rc);
        if (kp_policydb_destroy) kp_policydb_destroy(pdb);
        goto out_free;
    }

    *(void **)pol = sidtab; /* policy->sidtab @0 */
    g_backup_policy = pol;
    g_backup_ready = true;
    log_boot("selinux_sepolicy: deep copy ready (blob len %zu, allow_unknown %d, pdb %llx, sidtab %llx)\n",
             len, g_backup_allow_unknown, (unsigned long)pdb, (unsigned long)sidtab);
    kp_probe_snapshot_domains();

    /* The load-capture path only stores a blob when it observes a marker-free
     * load.  On devices whose manager patches the policy before/at the first
     * observed load that never happens, and /sys/fs/selinux/policy would then
     * stay live while the transaction nodes answer from this snapshot -- the
     * self-contradiction the feature exists to avoid.  Adopt the clean policy
     * this snapshot was built from. */
    if (owned && live_clean && !g_clean_blob) {
        g_clean_blob = data;
        g_clean_blob_len = len;
        g_clean_locked = true;
        owned = false;
        log_boot("selinux_sepolicy: adopted the clean live policy as the served blob (%zu bytes)\n", len);
    }

    rc = 0;
    goto out;

out_free:
    if (pol) kp_vfree(pol);
    if (sidtab) kp_vfree(sidtab);
out:
    if (owned && data && kfunc(kvfree)) kfunc(kvfree)(data);
    return rc;
}

int selinux_sepolicy_snapshot(void)
{
    if (!selinux_sepolicy_supported()) return -EOPNOTSUPP;
    if (g_backup_ready) return 0;
    return kp_dup_sepolicy();
}

bool selinux_sepolicy_backup_ready(void)
{
    return g_backup_ready;
}

const void *selinux_sepolicy_clean_blob(size_t *len)
{
    if (len) *len = 0;
    if (!g_clean_blob || !g_clean_blob_len || !g_clean_locked) return NULL;
    if (len) *len = g_clean_blob_len;
    return g_clean_blob;
}

/* ---- query helpers against the deep copy ---- */

static struct policydb *kp_backup_policydb(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return (struct policydb *)((char *)g_backup_policy + KP_POLICY_POLICYDB_OFFSET);
}

static void *kp_backup_sidtab(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return *(void **)g_backup_policy;
}

/* ---- accessors for the legacy evaluator (selinux_hide_legacy.c) ---- */

/* kmalloc for strings handed back to callers that free with kp_kernel_str_free
 * (kfree); NULL when only vmalloc would work, because the two cannot be mixed. */
void *selinux_sepolicy_kmalloc(unsigned long size)
{
    bool via_vmalloc = false;
    void *p = kp_payload_alloc(size, KP_GFP_KERNEL, &via_vmalloc);

    if (via_vmalloc) {
        kp_payload_free(p, true);
        return NULL;
    }
    return p;
}

void *selinux_sepolicy_policydb(void)
{
    return kp_backup_policydb();
}

void *selinux_sepolicy_sidtab(void)
{
    return kp_backup_sidtab();
}

/* Clean context of a SID, for the backend that has to evaluate the decision
 * itself.  NULL when the copy has no such SID. */
struct context *selinux_sepolicy_sid_context(u32 sid)
{
    void *sidtab = kp_backup_sidtab();

    if (!g_backup_ready || !sidtab) return NULL;
    return kp_sidtab_context(sidtab, sid, NULL);
}

/* Parse a context string against the copy (no live-policy side effects). */
int selinux_sepolicy_parse_context(const char *scontext, u32 scontext_len, struct context *out)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();

    if (!g_backup_ready || !policydb || !sidtab || !out) return -ENOSYS;
    return kp_string_to_context_into(policydb, sidtab, scontext, scontext_len, KP_GFP_KERNEL, out);
}

/* ---- query helpers against the backup policy ---- */

/* Parse one context string against the copy's policydb/sidtab.  Shared by the
 * SID path and the legacy evaluator (which parses without registering). */
static int kp_string_to_context_into(struct policydb *policydb, void *sidtab, const char *scontext,
                                     u32 scontext_len, gfp_t gfp, struct context *out)
{
    char *scontext2;
    bool via_vmalloc = false;
    int rc;

    if (!policydb || !sidtab || !scontext_len || !out) return -EINVAL;
    if (selinux_hide_is_new_version() ? !kp_string_to_context_struct
                                      : !kp_string_to_context_struct_6)
        return -ENOSYS;
    if (scontext_len >= KP_CONTEXT_PAYLOAD_LIMIT) return -EINVAL;

    scontext2 = kp_payload_alloc(scontext_len + 1, gfp, &via_vmalloc);
    if (!scontext2) return -ENOMEM;
    lib_memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = '\0';

    lib_memset(out, 0, sizeof(*out));
    if (selinux_hide_is_new_version())
        rc = kp_string_to_context_struct(policydb, sidtab, scontext2, out, SECSID_NULL);
    else
        rc = kp_string_to_context_struct_6(policydb, sidtab, scontext2, scontext_len, out,
                                           SECSID_NULL);
    kp_payload_free(scontext2, via_vmalloc);
    return rc;
}

static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct context context;
    int rc;

    (void)def_sid;
    if (!policydb || !sidtab || !scontext_len) return -EINVAL;
    if (!kp_sidtab_context_to_sid) return -ENOSYS;

    rc = kp_string_to_context_into(policydb, sidtab, scontext, scontext_len, gfp, &context);
    /* On failure the in-kernel parser has already destroyed the partial context
     * (string_to_context_struct() does so on every error path). */
    if (rc) return rc;

    rc = kp_sidtab_context_to_sid(sidtab, &context, out_sid);
    /* The sidtab keeps its own copy; the MLS range allocated while parsing is
     * ours and only this call releases it.  Without it every accepted query
     * leaks two ebitmap nodes (128 B) that nothing reclaims. */
    kp_context_destroy(&context);
    return rc;
}

/* sid -> context through whichever accessor this kernel has: entry-based on
 * 5.10+, context-returning on 4.9 - 5.9.  *out_entry is the sidtab entry when
 * the accessor returns one (needed by the sid2str cache), NULL otherwise. */
static struct context *kp_sidtab_context(void *sidtab, u32 sid, struct sidtab_entry **out_entry)
{
    struct sidtab_entry *entry;

    if (out_entry) *out_entry = NULL;
    if (kp_sidtab_search_entry) {
        entry = kp_sidtab_search_entry(sidtab, sid);
        if (!entry) return NULL;
        if (out_entry) *out_entry = entry;
        return &entry->context;
    }
    /* 4.9 - 5.9: sidtab_search() already returns the context, and so does the
     * same-generation sidtab_search_core().  Prefer sidtab_search(): the core
     * variant was reshaped to return an entry by 5.10, where
     * sidtab_search_entry() above takes over anyway. */
    if (kp_sidtab_search) return kp_sidtab_search(sidtab, sid);
    if (kp_sidtab_search_core) {
        entry = kp_sidtab_search_core(sidtab, sid, 0);
        if (!entry) return NULL;
        if (out_entry) *out_entry = entry;
        return &entry->context;
    }
    return NULL;
}

/* context_struct_to_string() gained the policydb argument in 4.17 and kept it
 * when 6.6 dropped selinux_state from the ss/ helpers: 4.9 - 4.16 is the
 * 3-argument form, 4.17+ is (policydb, context, out, len) on every version
 * including 6.6/6.12.  This is a policydb question, not the state question --
 * keying it off ss_takes_state() sent 6.6+ into the 3-argument call with a
 * struct context in the policydb slot. */
static bool kp_to_string_takes_policydb(void)
{
    return kver >= VERSION(4, 17, 0);
}

static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct sidtab_entry *entry = NULL;
    struct context *ctx;
    int rc;

    if (scontext) *scontext = NULL;
    *scontext_len = 0;
    if (!policydb || !sidtab) return -EINVAL;

    ctx = kp_sidtab_context(sidtab, sid, &entry);
    if (!ctx) return -EINVAL;

    if (kp_legacy_to_string) {
        /* Legacy kernels render with the global policydb; the registered
         * renderer names the copy's symbols instead. */
        return kp_legacy_to_string(policydb, ctx, scontext, scontext_len);
    }

    if (kp_sidtab_sid2str_get && entry) {
        rc = kp_sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);
        if (rc != -ENOENT) return rc;
    }
    if (kp_to_string_takes_policydb()) {
        if (!kp_context_struct_to_string) return -EINVAL;
        rc = kp_context_struct_to_string(policydb, ctx, scontext, scontext_len);
    } else {
        if (!kp_context_struct_to_string_3) return -EINVAL;
        rc = kp_context_struct_to_string_3(ctx, scontext, scontext_len);
    }
    if (!rc && scontext && kp_sidtab_sid2str_put && entry)
        kp_sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct context *scontext, *tcontext;

    if (!policydb || !sidtab) return;
    if (kp_legacy_compute_av) {
        scontext = kp_sidtab_context(sidtab, ssid, NULL);
        if (!scontext) return;
        tcontext = kp_sidtab_context(sidtab, tsid, NULL);
        if (!tcontext) return;
        kp_legacy_compute_av(policydb, scontext, tcontext, tclass, avd);
        return;
    }
    if (!kp_context_struct_compute_av) return;
    if (!kp_sidtab_search && !kp_sidtab_search_entry && !kp_sidtab_search_core) return;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = KP_AVD_CLEAN_SEQNO;
    avd->flags = 0;

    scontext = kp_sidtab_context(sidtab, ssid, NULL);
    if (!scontext) return;

    tcontext = kp_sidtab_context(sidtab, tsid, NULL);
    if (!tcontext) return;

    if (unlikely(!tclass)) {
        if (g_backup_allow_unknown) avd->allowed = 0xffffffff;
        return;
    }

    kp_context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, NULL);
}

/* ---- public query dispatch ----
 * All of them answer through the ss/ wrappers on top of the deep copy, so the
 * same code serves every supported kernel; a wrapper whose symbols did not
 * resolve reports -ENOSYS.  (The old fake selinux_state route is gone: a
 * zero-initialized fake state has no policy and would fault inside the kernel's
 * state-based helpers on every retrieval.) */

int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_context_to_sid_with_policy(scontext, scontext_len, out_sid, SECSID_NULL, gfp);
}

int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_sid_to_context_with_policy(sid, scontext, scontext_len);
}

int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_context_to_sid_with_policy(scontext, lib_strlen(scontext), out_sid, SECSID_NULL, gfp);
}

void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    if (!g_backup_ready) return;
    kp_compute_av_user_with_policy(ssid, tsid, tclass, avd);
}

/*
 * The status page is not a function of the kernel version.  It is allocated on
 * the first open, initialised to sequence=0 / policyload=0, and both
 * selinux_status_update_policyload() and selinux_status_update_setenforce()
 * bump sequence by 2 -- and drop the update entirely while
 * selinux_state.status_page is still NULL.
 *
 * The only local fact that maps to a clean timeline is therefore whether the
 * page exists by the time the fake page is built (post-fs-data, i.e. after the
 * boot policy load):
 *
 *   page present : a clean device saw the boot load, so it reads 4/1 -- or
 *                  2/1 when still permissive, where no enforce bump happened.
 *   page absent  : a clean device saw no load either, so it reads 0/0.
 *                  Claiming 4/1 here would invent a load the page never saw.
 *   unknown      : no BTF / no struct selinux_state (pre-4.17); stay at 0/0,
 *                  which is what those kernels produce without the
 *                  pre-allocation patch.
 *
 * A device with extra reloads (the live page reads e.g. 14/8) still gets the
 * clean answer: that is the disguise.  Unlike a version constant it never
 * claims a timeline the page cannot have, and a 6.6 kernel that opened the
 * page early is handled correctly.
 */
static unsigned long kp_status_state_addr(void)
{
    static unsigned long addr;

    if (!addr) addr = lookup_name_with_suffix("selinux_state");
    return addr;
}

/* The status page is pre-allocated by init_sel_fs() only from 6.10 on (the
 * "(void) selinux_kernel_status_page()" call at the end of init_sel_fs); 6.6 -
 * 6.9 create it on the first open, which on a clean device happens after the
 * boot policy load, so their counters start and stay at 0/0.  A 6.6 device can
 * still show a live status page when some process opens it early, but
 * reporting 4/1 there claims a timeline the kernel cannot produce: the page
 * did not exist when the boot load committed.  Keep the version floor and
 * report the modern counters only from 6.10 on (2/1 while still permissive,
 * where the enforce switch never bumped sequence). */
static bool kp_clean_status_modern(void)
{
    return kver >= VERSION(6, 10, 0);
}

static u32 kp_status_enforcing(void)
{
    static long off = -2;
    unsigned long addr = kp_status_state_addr();

    if (off == -2) off = kp_btf_member_offset("selinux_state", "enforcing");
    if (!addr || off < 0 || off > 240) return 1;
    return *(volatile u8 *)(addr + (unsigned long)off) ? 1 : 0;
}

u32 selinux_sepolicy_clean_seq(void)
{
    if (!kp_clean_status_modern()) return 0;
    return kp_status_enforcing() ? KP_CLEAN_STATUS_SEQUENCE : 2;
}

u32 selinux_sepolicy_clean_policyload(void)
{
    return kp_clean_status_modern() ? KP_CLEAN_STATUS_POLICYLOAD : 0;
}

int selinux_sepolicy_clean_deny_unknown(void)
{
    if (!g_backup_ready) return 1;
    return g_backup_allow_unknown ? 0 : 1;
}

/* ---- init ---- */

int selinux_sepolicy_init(void)
{
    static bool done;
    unsigned long addr;

    /* selinux_sepolicy_boot_init() installs the load hook first; this one runs
     * at post-fs-data and resolves the rest.  Guard the whole body so the
     * argument-redirect hooks below (4.9 - 4.19) can never be installed twice
     * if the init entry point is ever reached again. */
    if (done) return 0;
    done = true;

    if (!selinux_sepolicy_supported()) {
        log_boot("selinux_sepolicy: requires kernel >= 4.9 (kver %x)\n", kver);
        return -EOPNOTSUPP;
    }

    /* ss/ internals used by the deep copy and the query wrappers: try the exact
     * kallsyms name first, then fall back to the suffix-tolerant lookup for
     * clang-LTO kernels that mangle static names to <name>.<n> /
     * <name>.llvm.<hash>. */
    kp_policydb_read = (policydb_read_fn)lookup_name_with_suffix("policydb_read");
    kp_policydb_load_isids = (policydb_load_isids_fn)lookup_name_with_suffix("policydb_load_isids");
    kp_policydb_destroy = (policydb_destroy_fn)lookup_name_with_suffix("policydb_destroy");
    kp_ebitmap_destroy = (ebitmap_destroy_fn)lookup_name_with_suffix("ebitmap_destroy");
    if (!kp_ebitmap_destroy)
        logkfw("selinux_sepolicy: ebitmap_destroy unresolved, parsed MLS contexts will leak\n");

    kp_string_to_context_struct = (string_to_context_struct_fn)lookup_name_with_suffix("string_to_context_struct");
    kp_string_to_context_struct_6 =
        (string_to_context_struct_6_fn)lookup_name_with_suffix("string_to_context_struct");
    kp_sidtab_context_to_sid = (sidtab_context_to_sid_fn)lookup_name_with_suffix("sidtab_context_to_sid");
    kp_sidtab_search_entry = (sidtab_search_entry_fn)lookup_name_with_suffix("sidtab_search_entry");
    kp_sidtab_search = (sidtab_search_fn)lookup_name_with_suffix("sidtab_search");
    kp_sidtab_sid2str_get = (sidtab_sid2str_get_fn)lookup_name_with_suffix("sidtab_sid2str_get");
    kp_sidtab_sid2str_put = (sidtab_sid2str_put_fn)lookup_name_with_suffix("sidtab_sid2str_put");
    kp_context_struct_to_string = (context_struct_to_string_fn)lookup_name_with_suffix("context_struct_to_string");
    kp_context_struct_to_string_3 =
        (context_struct_to_string_3_fn)lookup_name_with_suffix("context_struct_to_string");
    kp_sidtab_search_core = (sidtab_search_core_fn)lookup_name_with_suffix("sidtab_search_core");
    kp_context_struct_compute_av = (context_struct_compute_av_fn)lookup_name_with_suffix("context_struct_compute_av");
    kp_payload_resolve();
    if (!selinux_hide_legacy_required()) {
        /* Only the argument-redirect hooks are needed: the deep copy is consumed by
        * swapping the policydb argument while an app query runs. */
        addr = lookup_name_with_suffix("context_struct_compute_av");
        if (addr) {
            hook_wrap6((void *)addr, before_context_struct_compute_av, NULL, NULL);
            log_boot("selinux_sepolicy: hooked context_struct_compute_av @ %llx\n", addr);
        }
        addr = lookup_name_with_suffix("string_to_context_struct");
        if (addr) {
            hook_wrap5((void *)addr, before_string_to_context_struct, NULL, NULL);
            log_boot("selinux_sepolicy: hooked string_to_context_struct @ %llx\n", addr);
        }
        g_policydb_redirect_active = true;
    }

    /* Capture policy blobs as they are loaded, so the clean copy comes from the
     * full platform policy and not from an earlier (or later, patched) epoch.
     * Idempotent: the boot-time init usually got here first. */
    kp_install_load_hook();

    log_boot("selinux_sepolicy: read=%llx str2ctx=%llx sidtab2sid=%llx search=%llx\n",
             (unsigned long)kfunc(security_read_policy), (unsigned long)kp_string_to_context_struct,
             (unsigned long)kp_sidtab_context_to_sid, (unsigned long)kp_sidtab_search_entry);
    log_boot("selinux_sepolicy: sid2str=%llx ctx2str=%llx search_core=%llx compute_av=%llx\n",
             (unsigned long)kp_sidtab_sid2str_get, (unsigned long)kp_context_struct_to_string,
             (unsigned long)kp_sidtab_search_core, (unsigned long)kp_context_struct_compute_av);
    return 0;
}
