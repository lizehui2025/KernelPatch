/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Built-in selinux_hide feature, 
 * 
 *
 * The kernel is driven by the post-fs-data before/after events reported via
 * 
 * keys off: "post-fs-data"/"before" installs the hooks (and honors the
 * /data/adb/ap/selinux_hide control file), "after" is the finalize point.
 *
 * Supported only on kernels >= 4.19; below that even a forced enable is a
 * no-op (see selinux_hide_control / selinux_hide_enable).
 *
 * On every supported kernel (>= 4.19) the context/access/setprocattr hooks
 * answer against a KernelSU-style deep copy of the policy taken at post-fs-data
 * "before" while the live policy is still untouched, so a root app sees the
 * pre-modification policy.  Apps (uid >= 10000) also see a fake
 * /sys/fs/selinux/status (enforcing=1, clean seqno), hiding permissive /
 * disabled SELinux and policy reloads.
 */

#include <selinux_hide.h>
#include <selinux_sepolicy.h>

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <predata.h>
#include <kputils.h>
#include <pgtable.h>
#include <baselib.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>
#include <kbtf.h>
#include <selinux_hide.h>
/* ---- feature constants ---- */
#ifdef ANDROID
extern int android_is_safe_mode;
#endif

#define KP_SELINUX_HIDE_FILE "/data/adb/ap/selinux_hide"
#define KP_SELINUX_HIDE_STRICT_FILE "/data/adb/ap/selinux_hide_strict"

#define KP_O_RDONLY 0
#define KP_PAGE_SIZE 4096
#define KP_TRANSACTION_ARGRESP 8
static size_t kp_transaction_limit(void)
{
    return (page_size > 0 ? (size_t)page_size : (size_t)KP_PAGE_SIZE) - KP_TRANSACTION_ARGRESP;
}
#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */

/* Stack scratch for the snapshot lookup: the payload is tokenized in place, so
 * the handler needs a writable copy of it.  A context string is a few dozen
 * bytes, this covers every real query and the oversized ones fall back to the
 * allocating variant, which has the same verdicts. */
#define KP_CONTEXT_SCRATCH 512

/* SELinux class / permission constants, matching
 * security/selinux/include/classmap.h (class numbers are 1-based indices). */
#define KP_SECCLASS_SECURITY 1
#define KP_SECCLASS_PROCESS 2
#define KP_SECINITSID_SECURITY 2 /* initial SIDs: kernel=1, security=2 */
#define KP_SECURITY__COMPUTE_AV (1U << 0)
#define KP_SECURITY__CHECK_CONTEXT (1U << 3)
#define KP_PROCESS__SETCURRENT (1U << 24)
#define SEL_WRITE_OP_CONTEXT 5
#define SEL_WRITE_OP_ACCESS 6
/* struct selinux_kernel_status (20 bytes) */
#define KP_SELINUX_KERNEL_STATUS_VERSION 1
#define KP_SELINUX_STATUS_SIZE 20

/* ---- state ---- */

static bool selinux_hide_enabled;
static bool selinux_hide_approved; /* /data/adb/ap/selinux_hide seen at "before" */

typedef void (*security_cred_getsecid_fn)(const struct cred *c, u32 *secid);
static security_cred_getsecid_fn kp_security_cred_getsecid;

typedef int (*remap_pfn_range_fn)(struct vm_area_struct *vma, unsigned long addr, unsigned long pfn,
                                  unsigned long size, unsigned long prot);
static remap_pfn_range_fn kp_remap_pfn_range;

typedef ssize_t (*sel_write_op_fn)(struct file *file, char *buf, size_t size);
typedef int (*sel_mmap_status_fn)(struct file *, struct vm_area_struct *);
typedef ssize_t (*sel_read_status_fn)(struct file *, char __user *, size_t, loff_t *);
typedef int (*selinux_setprocattr_fn)(const char *, void *, size_t);
/* < 6.6 avc_has_perm ABI takes the global selinux_state as the first argument. */
typedef int (*avc_has_perm_compat_fn)(void *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, void *auditdata);

static unsigned long sel_write_context_addr;
static unsigned long sel_write_access_addr;
static unsigned long sel_read_handle_status_addr;
static unsigned long sel_mmap_handle_status_addr;
static unsigned long selinux_setprocattr_addr;

static sel_write_op_fn orig_context_write;
static sel_write_op_fn orig_access_write;
static selinux_setprocattr_fn orig_setprocattr;
static sel_read_status_fn orig_sel_read_handle_status;
static sel_mmap_status_fn orig_sel_mmap_handle_status;

static unsigned char fake_status_bytes[KP_SELINUX_STATUS_SIZE];
static void *fake_status_vaddr; /* vmalloc'd page mapped for uid >= 10000 */

static unsigned long g_hooked[8];
static int g_hooked_cnt;

static bool g_hooked_context;
static bool g_hooked_access;
static bool g_hooked_status_read;
static bool g_hooked_status_mmap;

static bool g_eval_busy_warned;
static bool g_setprocattr_busy_warned;

/* ---- helpers ---- */

#define KP_QLOG_OFF 0
#define KP_QLOG_ON 1
#define KP_QLOG_VERBOSE 2

static int selinux_hide_query_log = KP_QLOG_OFF;

/* Printable, bounded, NUL-terminated copy of a query string. */
static void kp_qlog_str(char *dst, const void *src, size_t len, size_t max)
{
    const char *s = src;
    size_t i, n = len < max ? len : max;

    for (i = 0; i < n; i++) {
        char c = s[i];
        dst[i] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    dst[n] = '\0';
}

static void kp_qlog(const char *what, uid_t uid, const void *detail, size_t dlen)
{
    char s[96];

    if (selinux_hide_query_log == KP_QLOG_OFF) return;
    kp_qlog_str(s, detail, dlen, sizeof(s) - 1);
    logkfi("query %s uid=%u: %s\n", what, (unsigned int)uid, s);
}

static void kp_qlog_plain(const char *what, uid_t uid)
{
    if (selinux_hide_query_log == KP_QLOG_OFF) return;
    logkfi("query %s uid=%u\n", what, (unsigned int)uid);
}

/* ---- per-stage attribution ----
 *
 * An app that submits a selinuxfs query times it with its own clock, so the only
 * way to know which part of an answer costs what is to measure it on this side.
 * With the query log at KP_QLOG_VERBOSE each hooked handler stamps ktime_get()
 * around its stages and prints one line per query, in nanoseconds.  At
 * KP_QLOG_ON or below the whole block costs one comparison against
 * KP_QLOG_VERBOSE, so the numbers are collected only on demand and never change
 * a decision: the stage values land in the globals below and a query that was
 * not traced simply leaves them untouched.
 */
/* Diagnostic builds set KP_TRACE_BUDGET to attribute their first N app queries
 * without a manager that can reach the verbose level; a normal build leaves it
 * at zero and the whole block is two comparisons. */
#ifndef KP_TRACE_BUDGET
#define KP_TRACE_BUDGET 0
#endif
static int g_trace_budget = KP_TRACE_BUDGET;

static bool kp_trace_stages(void)
{
    return selinux_hide_query_log == KP_QLOG_VERBOSE || g_trace_budget > 0;
}

typedef long long (*kp_clock_fn)(void);
static kp_clock_fn kp_clock_ns;

/* Nanoseconds on the monotonic clock the kernel's own tracing uses.  A missing
 * symbol turns the stamps into zeros, which shows up as zero deltas in the log
 * instead of as a bogus attribution. */
static long long kp_now_ns(void)
{
    if (!kp_clock_ns)
        kp_clock_ns = (kp_clock_fn)lookup_name_with_suffix("ktime_get");
    if (!kp_clock_ns)
        kp_clock_ns = (kp_clock_fn)lookup_name_with_suffix("local_clock");
    return kp_clock_ns ? kp_clock_ns() : 0;
}

/* Filled by kp_context_to_sid_clean_buf() while stages are traced. */
static long long g_stage_snap_ns;
static long long g_stage_live_ns;

/* Read by selinux_sepolicy.c for its level-2 (internal redirect) logging. */
int selinux_hide_query_log_level(void)
{
    return selinux_hide_query_log;
}

static unsigned long kp_selinux_state_addr;

static u32 kp_live_enforcing(void)
{
    static long off = -2;
    unsigned long addr = kp_selinux_state_addr;

    if (off == -2) off = kp_btf_member_offset("selinux_state", "enforcing");
    if (!addr) addr = lookup_name_with_suffix("selinux_state");
    if (!addr || off < 0 || off > 120) return 1;
    return *(volatile u8 *)(addr + (unsigned long)off) ? 1 : 0;
}

static void put_u32_le(unsigned char *dst, u32 value)
{
    dst[0] = (unsigned char)(value & 0xff);
    dst[1] = (unsigned char)((value >> 8) & 0xff);
    dst[2] = (unsigned char)((value >> 16) & 0xff);
    dst[3] = (unsigned char)((value >> 24) & 0xff);
}

static void fill_fake_status_bytes(void)
{
    u32 seq = selinux_sepolicy_clean_seq();
    u32 pload = 0;

    lib_memset(fake_status_bytes, 0, sizeof(fake_status_bytes));
    put_u32_le(fake_status_bytes + 0, KP_SELINUX_KERNEL_STATUS_VERSION);
    put_u32_le(fake_status_bytes + 4, seq);
    put_u32_le(fake_status_bytes + 8, kp_live_enforcing());
    put_u32_le(fake_status_bytes + 12, pload);
    put_u32_le(fake_status_bytes + 16, (u32)selinux_sepolicy_clean_deny_unknown());
}

static void init_fake_status(void)
{
    unsigned long size = page_size > 0 ? (unsigned long)page_size : KP_PAGE_SIZE;

    if (!fake_status_vaddr) {
        void *p = kp_vmalloc(size);
        if (!p) {
            logkfw("selinux_hide: vmalloc unavailable, fake status disabled\n");
            return;
        }
        lib_memset(p, 0, size);
        fake_status_vaddr = p;
        logkfi("selinux_hide: fake status page ready (%lu bytes)\n", size);
    }
    lib_memcpy(fake_status_vaddr, fake_status_bytes, sizeof(fake_status_bytes));
}

#define KP_VMA_VM_START_OFF 0
#define KP_VMA_VM_END_OFF 8

#define KP_VM_READ 0x00000001UL
#define KP_VM_WRITE 0x00000002UL
#define KP_VM_MAYREAD 0x00000010UL
#define KP_VM_MAYWRITE 0x00000020UL

static long g_vma_page_prot_off = -1;
static long g_vma_vm_flags_off = -1;
static long g_vma_vm_pgoff_off = -1;
static long g_vma_vm_file_off = -1;

#define KP_ADDR_TAG_BITS (0xFUL << 56)
static unsigned long kp_untag_addr(unsigned long addr)
{
    return addr & ~KP_ADDR_TAG_BITS;
}

static bool kp_vma_off_ok(long off)
{
    return off >= 0 && off < 256 && (off & 7) == 0;
}

static void kp_resolve_vma_offsets(void)
{
    long prot = -1, flags = -1, pgoff = -1, file = -1, size = -1;

    if (kp_btf_available()) {
        prot = kp_btf_member_offset("vm_area_struct", "vm_page_prot");
        flags = kp_btf_member_offset("vm_area_struct", "vm_flags");
        pgoff = kp_btf_member_offset("vm_area_struct", "vm_pgoff");
        file = kp_btf_member_offset("vm_area_struct", "vm_file");
        size = kp_btf_type_size("vm_area_struct");
        if (kp_vma_off_ok(prot) && kp_vma_off_ok(flags) && flags > prot &&
            kp_vma_off_ok(pgoff) && kp_vma_off_ok(file) && file > pgoff &&
            size > 0 && pgoff + 8 <= size && file + 8 <= size) {
            g_vma_page_prot_off = prot;
            g_vma_vm_flags_off = flags;
            g_vma_vm_pgoff_off = pgoff;
            g_vma_vm_file_off = file;
            log_boot("selinux_hide: vm_area_struct offsets from BTF: "
                     "vm_page_prot %ld, vm_flags %ld, vm_pgoff %ld, vm_file %ld\n",
                     prot, flags, pgoff, file);
            return;
        }
        log_boot("selinux_hide: vm_area_struct BTF lookup incomplete "
                 "(vm_page_prot %ld, vm_flags %ld, vm_pgoff %ld, vm_file %ld)\n",
                 prot, flags, pgoff, file);
    }
    if (kver >= VERSION(6, 1, 0)) {
        g_vma_page_prot_off = 24;
        g_vma_vm_flags_off = 32;
    } else {
        g_vma_page_prot_off = 72;
        g_vma_vm_flags_off = 80;
    }
    log_boot("selinux_hide: vm_area_struct offsets from version table: vm_page_prot %ld, vm_flags %ld\n",
             g_vma_page_prot_off, g_vma_vm_flags_off);
}

static unsigned long kp_vma_page_prot_off(void)
{
    if (g_vma_page_prot_off > 0) return (unsigned long)g_vma_page_prot_off;
    return kver >= VERSION(6, 1, 0) ? 24 : 72;
}

static unsigned long kp_vma_vm_flags_off(void)
{
    if (g_vma_vm_flags_off > 0) return (unsigned long)g_vma_vm_flags_off;
    return kver >= VERSION(6, 1, 0) ? 32 : 80;
}

static bool kp_pgprot_plausible(unsigned long prot)
{
    return (prot & 0x3) == 0x3 &&
           (prot & 0x0000FFFFFFF000UL) == 0 &&
           (prot >> 55) == 0;
}

/* ---- permission / sid helpers (KernelSU my_write_* parity) ---- */

static avc_has_perm_compat_fn kp_avc_has_perm_compat;

static u32 kp_current_sid(void)
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    u32 sid = 0;
    if (!kp_security_cred_getsecid || !cred) return 0;
    kp_security_cred_getsecid(cred, &sid);
    return sid;
}

/* avc_has_perm(current_sid, tsid, tclass, requested).  0 = granted (or the
 * check is unavailable, which matches stock behaviour for untrusted_app). */
static int kp_avc_check(u32 tsid, u16 tclass, u32 requested)
{
    u32 mysid = kp_current_sid();
    if (!mysid) return 0;
    if (selinux_hide_is_without_sepolicy_state_version()) {
        if (!kfunc(avc_has_perm)) return 0;
        return kfunc(avc_has_perm)(mysid, tsid, tclass, requested, NULL);
    }
    if (!kp_avc_has_perm_compat)
        kp_avc_has_perm_compat = (avc_has_perm_compat_fn)lookup_name_with_suffix("avc_has_perm");
    if (!kp_avc_has_perm_compat || !kp_selinux_state_addr) return 0;
    return kp_avc_has_perm_compat((void *)kp_selinux_state_addr, mysid, tsid, tclass, requested, NULL);
}

int security_context_to_sid_fn(const char *context, int len, u32 *sid, gfp_t gfp);

/*
 * Resolve an app-supplied context: the clean snapshot decides whether it is
 * known, and the live policy is consulted only for a context the snapshot
 * accepted.
 *
 * The live lookup reproduces a stock query's registration side effect: selinuxfs
 * resolves a context in the live policy, which inserts it into the live SID
 * table.  That is what keeps a SID handed out by the snapshot resolvable
 * through the live policy -- KernelSU a810677b, "fix sidtab detection" -- and
 * the table's size is readable by anyone through
 * /sys/fs/selinux/ss/sidtab_hash_stats, so the registration is observable.
 *
 * It must NOT run for a context the snapshot rejects: the live policy is where
 * a root manager's extra domains live, so resolving a hidden name
 * (u:r:su:s0, u:r:ksu:s0, ...) there would register it while the answer says
 * "unknown".  An app watching that counter would see the live table grow on a
 * rejected query, which no clean device does, and could enumerate the hidden
 * policy with a wordlist.  Confining the lookup to the accepted path also keeps
 * a rejected name exactly as expensive as the snapshot's own failed parse,
 * whether or not the live policy knows it, so the rejected inputs cannot be
 * told apart by cost either.
 *
 * Returns the snapshot's verdict: 0 = the context is answered from the snapshot
 * and *sid is its SID.
 */
static int kp_context_to_sid_clean(const char *scontext, u32 scontext_len, u32 *sid)
{
    u32 live_sid = SECSID_NULL;
    int rc;

    *sid = SECSID_NULL;
    rc = selinux_sepolicy_context_to_sid(scontext, scontext_len, sid, KP_GFP_KERNEL);
    if (!rc)
        (void)security_context_to_sid_fn(scontext, scontext_len, &live_sid, KP_GFP_KERNEL);
    return rc;
}

/*
 * The same verdict, resolved from a caller-owned writable scratch buffer.
 *
 * The snapshot lookup tokenizes its input in place, so the variant above makes
 * a private copy of the payload for every query.  A caller that already parsed
 * the payload into a stack buffer can hand over a copy instead and save the
 * allocator round trip; `work` must hold scontext_len + 1 bytes, and `scontext`
 * stays intact because the live lookup below still needs the original text.
 *
 * The decision itself must not change: only an accepted context is registered
 * in the live policy (see kp_context_to_sid_clean).
 */
static int kp_context_to_sid_clean_buf(char *work, const char *scontext, u32 scontext_len, u32 *sid)
{
    u32 live_sid = SECSID_NULL;
    bool trace = kp_trace_stages();
    long long t0 = trace ? kp_now_ns() : 0;
    long long t1 = 0;
    int rc;

    *sid = SECSID_NULL;
    lib_memcpy(work, scontext, scontext_len);
    work[scontext_len] = '\0';
    rc = selinux_sepolicy_context_to_sid_inplace(work, scontext_len, sid);
    if (trace) t1 = kp_now_ns();
    if (!rc) {
        (void)security_context_to_sid_fn(scontext, scontext_len, &live_sid, KP_GFP_KERNEL);
        if (trace) g_stage_live_ns = kp_now_ns() - t1;
    } else if (trace) {
        g_stage_live_ns = 0;
    }
    if (trace) g_stage_snap_ns = t1 - t0;
    return rc;
}

static ssize_t kp_patch_response_seqno(char *buf, ssize_t ret, u32 new_seqno)
{
    char *p = buf, *end = buf + ret, *tok_start;
    char new_str[12];
    int ns_len, tok, i;
    ssize_t diff;

    if (ret <= 0 || !buf) return ret;
    for (tok = 0; tok < 4; tok++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    tok_start = p;
    while (p < end && *p != ' ' && *p != '\0' && *p != '\n') p++;
    if (tok_start >= p) return ret;

    {
        u32 v = new_seqno;
        char tmp[12];
        if (v == 0) {
            new_str[0] = '0';
            ns_len = 1;
        } else {
            i = 0;
            while (v > 0) {
                tmp[i++] = '0' + (v % 10);
                v /= 10;
            }
            for (ns_len = 0; ns_len < i; ns_len++)
                new_str[ns_len] = tmp[i - 1 - ns_len];
        }
    }

    diff = (ssize_t)ns_len - (ssize_t)(p - tok_start);
    if (diff != 0) {
        char *dst = tok_start + ns_len, *src = p;
        size_t move = (size_t)(end - src);
        int j;
        if (diff < 0) {
            for (j = 0; j < (int)move; j++) dst[j] = src[j];
        } else {
            for (j = (int)move - 1; j >= 0; j--) dst[j] = src[j];
        }
        ret += diff;
    }
    for (i = 0; i < ns_len; i++)
        tok_start[i] = new_str[i];
    return ret;
}

/* ---- app-facing selinuxfs query surface ----
 *
 * selinuxfs exposes the context-resolving transaction nodes context/access/
 * create/relabel/user/member (world-readable and world-writable at the VFS
 * level: S_IRUGO|S_IWUGO) and validatetrans (world-writable).  Which of them an
 * app-side caller can actually use is decided by the permission each handler
 * checks *before* it parses the payload:
 *
 *   context  (check_context)   -- hooked below, answered from the snapshot
 *   access   (compute_av)      -- hooked below, answered from the snapshot
 *   create   (compute_create)  -- no hook needed: AOSP grants none of these to
 *   relabel  (compute_relabel)    an app-side domain.  app_zygote is the only
 *   user     (compute_user)       app-uid domain with SELinux query rights and
 *   member   (compute_member)     selinux_check_access() gives it exactly
 *   validatetrans (validate_trans) compute_av + check_context, while plain app
 *                                 domains are denied both outright
 *                                 (private/app.te: "SELinux is not an API for
 *                                 apps to use").  The kernel checks the
 *                                 permission before parsing, so every app-side
 *                                 call to those five is rejected with EACCES
 *                                 before any policy lookup -- there is nothing
 *                                 to intercept there.
 *
 * setprocattr ("current") and the status page are hooked further down. */

static ssize_t my_write_context_new(struct file *file, char *buf, size_t size)
{

    uid_t uid = current_uid();
    char scratch[KP_CONTEXT_SCRATCH];
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;
    bool trace = kp_trace_stages();
    long long t0 = 0, t_log = 0, t_avc = 0, t_sid = 0, t_end = 0;

    if (trace) t0 = kp_now_ns();

    /* Before the permission check on purpose: the log is what makes detector
     * probes visible, and its cost depends only on the payload length, so two
     * equal-length writes cannot be told apart through it. */
    kp_qlog("context_write", uid, buf, size);
    if (trace) t_log = kp_now_ns();

    if (likely(uid < 10000)) {
        length = orig_context_write(file, buf, size);
        if (length > 0) kp_qlog("context_answer", uid, buf, (size_t)length);
        else kp_qlog("context_answer_failed", uid, buf, 0);
        return length;
    }

    /* KernelSU my_write_context: answer entirely from the clean snapshot.
     * The stock handler is never run for apps, so the live (patched) sidtab
     * can never leak into the canonical answer -- no symbol-redirect scope,
     * no silent fallback to the live policy. */
    length = kp_avc_check(KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__CHECK_CONTEXT);
    if (trace) t_avc = kp_now_ns();
    if (length) return length;

    /* The snapshot lookup tokenizes its payload in place, so the query needs a
     * writable copy of it.  A stack buffer covers every real context string and
     * saves an allocator round trip per query; an oversized payload keeps the
     * allocating variant, whose verdicts are identical. */
    if (trace) {
        /* Mark "not attributed" so an oversized payload cannot report the
         * previous query's stage times. */
        g_stage_snap_ns = -1;
        g_stage_live_ns = -1;
    }
    if (size < sizeof(scratch))
        length = kp_context_to_sid_clean_buf(scratch, buf, (u32)size, &sid);
    else
        length = kp_context_to_sid_clean(buf, size, &sid);
    if (trace) t_sid = kp_now_ns();
    if (length) {
        return length;
    }

    length = selinux_sepolicy_sid_to_context(sid, &canon, &len);
    if (trace) t_end = kp_now_ns();
    if (length) return length;

    if ((size_t)len > kp_transaction_limit()) {
        length = -ERANGE;
        goto out;
    }

    lib_memcpy(buf, canon, len);
    length = (ssize_t)len;
out:
    if (trace) {
        long long t_copy = kp_now_ns();
        logkfi("stage context uid=%u size=%u log=%lld avc=%lld snap=%lld live=%lld "
               "sid2str=%lld copy=%lld total=%lld\n",
               (unsigned int)uid, (unsigned int)size, t_log - t0, t_avc - t_log,
               g_stage_snap_ns, g_stage_live_ns, t_end - t_sid, t_copy - t_end,
               t_copy - t0);
        if (g_trace_budget > 0) g_trace_budget--;
    }
    if (canon) kp_kernel_str_free(canon);
    return length;
}
static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    if (selinux_hide_is_new_version()) return my_write_context_new(file, buf, size);
    uid_t uid = current_uid();
    ssize_t ret;

    kp_qlog("context_write", uid, buf, size);

    if (likely(uid < 10000)) {
        ret = orig_context_write(file, buf, size);
        if (ret > 0){ 
            kp_qlog("context_answer", uid, buf, (size_t)ret);
        }else{
            kp_qlog("context_answer_failed", uid, buf, 0);
        }
        return ret;
    }
    if (selinux_sepolicy_clean_eval_enter() == 0) {
        ret = orig_context_write(file, buf, size);
        selinux_sepolicy_clean_eval_leave();
    } else {
        if (!g_eval_busy_warned) {
            g_eval_busy_warned = true;
            logkfw("selinux_hide: context: redirect slots busy, query refused with -EAGAIN\n");
        }
        return -EAGAIN;
    }
    if (ret > 0) kp_qlog("context_answer", uid, buf, (size_t)ret);
    return ret;

}

#define KP_SEL_RESPONSE_RESERVE 64

static ssize_t kp_sel_reply(char *buf, const char *text, size_t n)
{
    size_t limit = kp_transaction_limit() - KP_SEL_RESPONSE_RESERVE;

    if (n >= limit) n = limit - 1;
    lib_memcpy(buf, text, n);
    buf[n] = 0;
    return (ssize_t)n;
}

/* ---- access payload: the two libc calls this path used to make ----
 *
 * Everything on this path is timed by whoever submits the query, so the cost of
 * the parser and of the formatter is part of the signal.  The stock handler
 * parses with sscanf("%255s %255s %hu") and prints with
 * snprintf("%x %x %x %x %u %x"); both run a full conversion engine per call,
 * which is a large share of what a query costs here.
 *
 * The fast parser deliberately handles only the input shape a real query has --
 * two whitespace-separated context strings and a plain decimal class -- and
 * reports failure for everything else (a field at the 255-byte width limit, a
 * signed or wrapped class, a missing field).  Those fall back to the exact
 * vsscanf call the handler used before, so malformed input -- the shape a
 * detector is most likely to probe with -- keeps the kernel's own behaviour.
 */

static bool kp_is_query_sep(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

/* One "%255s" field; false when the field is empty or would be cut by the
 * width limit, so neither case is decided by this code. */
static bool kp_read_query_word(const char **pp, char *dst)
{
    const char *p = *pp;
    u32 n = 0;

    while (kp_is_query_sep(*p)) p++;
    while (*p && !kp_is_query_sep(*p)) {
        if (n == 255) return false;
        dst[n++] = *p++;
    }
    if (!n) return false;
    dst[n] = '\0';
    *pp = p;
    return true;
}

static bool kp_parse_access_fast(const char *buf, char *scon, char *tcon, u16 *tclass)
{
    const char *p = buf;
    u32 v = 0;

    if (!kp_read_query_word(&p, scon)) return false;
    if (!kp_read_query_word(&p, tcon)) return false;

    while (kp_is_query_sep(*p)) p++;
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (u32)(*p++ - '0');
        if (v > 0xffff) return false;
    }
    *tclass = (u16)v;
    return true;
}

static u32 kp_put_hex(u32 v, char *dst)
{
    static const char hex[] = "0123456789abcdef";
    char tmp[8];
    u32 i = 0, n = 0;

    if (!v) {
        dst[0] = '0';
        return 1;
    }
    while (v) {
        tmp[i++] = hex[v & 0xf];
        v >>= 4;
    }
    while (i) dst[n++] = tmp[--i];
    return n;
}

static u32 kp_put_dec(u32 v, char *dst)
{
    char tmp[10];
    u32 i = 0, n = 0;

    if (!v) {
        dst[0] = '0';
        return 1;
    }
    while (v) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i) dst[n++] = tmp[--i];
    return n;
}

/* snprintf(out, 96, "%x %x %x %x %u %x", ...) without the format engine. */
static ssize_t kp_format_avd(char *out, size_t cap, const struct av_decision *avd)
{
    u32 n = 0;

    if (cap < 64) {
        return snprintf(out, cap, "%x %x %x %x %u %x",
                        avd->allowed, 0xffffffff, avd->auditallow, avd->auditdeny,
                        avd->seqno, avd->flags);
    }
    n += kp_put_hex(avd->allowed, out + n);    out[n++] = ' ';
    n += kp_put_hex(0xffffffffu, out + n);     out[n++] = ' ';
    n += kp_put_hex(avd->auditallow, out + n); out[n++] = ' ';
    n += kp_put_hex(avd->auditdeny, out + n);  out[n++] = ' ';
    n += kp_put_dec(avd->seqno, out + n);      out[n++] = ' ';
    n += kp_put_hex(avd->flags, out + n);
    return (ssize_t)n;
}

static ssize_t my_write_access_new(struct file *file, char *buf, size_t size)
{
    uid_t uid = current_uid();
    char scon[256], tcon[256], work[256];
    struct av_decision avd;
    u32 ssid, tsid, sconlen, tconlen;
    u16 tclass = 0;
    ssize_t length;
    bool trace = kp_trace_stages();
    long long t0 = 0, t_log = 0, t_avc = 0, t_parse = 0, t_conv = 0, t_avd = 0;
    long long snap_s = 0, live_s = 0, snap_t = 0, live_t = 0;

    if (trace) t0 = kp_now_ns();
    kp_qlog("access_write", uid, buf, size);
    if (trace) t_log = kp_now_ns();

    if (likely(uid < 10000)) {
        length = orig_access_write(file, buf, size);
        if (length > 0) kp_qlog("access_answer", uid, buf, (size_t)length);
        else kp_qlog("access_answer_failed", uid, buf, 0);
        return length;
    }

    length = kp_avc_check(KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__COMPUTE_AV);
    if (trace) t_avc = kp_now_ns();
    if (length) return length;

    if (!kp_parse_access_fast(buf, scon, tcon, &tclass)) {
        if (sscanf(buf, "%255s %255s %hu", scon, tcon, &tclass) != 3) return -EINVAL;
    }
    if (trace) t_parse = kp_now_ns();

    sconlen = lib_strlen(scon);
    tconlen = lib_strlen(tcon);

    /* Both contexts must be in the snapshot: a context only the live policy has
     * (the manager's su domain) is not part of the answer a clean device would
     * give.  Each accepted context is registered in the live policy as well,
     * exactly like the stock handler's own conversions do; a rejected one is
     * not, see kp_context_to_sid_clean. */
    length = kp_context_to_sid_clean_buf(work, scon, sconlen, &ssid);
    if (trace) {
        snap_s = g_stage_snap_ns;
        live_s = g_stage_live_ns;
    }
    if (length) return length;

    length = kp_context_to_sid_clean_buf(work, tcon, tconlen, &tsid);
    if (trace) {
        snap_t = g_stage_snap_ns;
        live_t = g_stage_live_ns;
        t_conv = kp_now_ns();
    }
    if (length) return length;

    lib_memset(&avd, 0, sizeof(avd));
    avd.auditdeny = 0xffffffff;
    selinux_sepolicy_compute_av_user(ssid, tsid, tclass, &avd);
    avd.seqno = KP_AVD_CLEAN_SEQNO;
    if (trace) t_avd = kp_now_ns();

    {
        char out[96];
        ssize_t n = (ssize_t)kp_format_avd(out, sizeof(out), &avd);
        ssize_t reply = kp_sel_reply(buf, out, (size_t)n);

        if (trace) {
            long long t_end = kp_now_ns();
            logkfi("stage access uid=%u size=%u log=%lld avc=%lld parse=%lld "
                   "scon(snap=%lld live=%lld) tcon(snap=%lld live=%lld) conv=%lld "
                   "avd=%lld fmt=%lld total=%lld\n",
                   (unsigned int)uid, (unsigned int)size, t_log - t0, t_avc - t_log,
                   t_parse - t_avc, snap_s, live_s, snap_t, live_t,
                   t_conv - t_parse, t_avd - t_conv, t_end - t_avd, t_end - t0);
            if (g_trace_budget > 0) g_trace_budget--;
        }
        return reply;
    }
}
static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (selinux_hide_is_new_version()) return my_write_access_new(file, buf, size);

    ssize_t ret;
    uid_t uid = current_uid();

    kp_qlog("access_write", uid, buf, size);

    if (likely(uid < 10000)) {
        ret = orig_access_write(file, buf, size);
        if (ret > 0) kp_qlog("access_answer", uid, buf, (size_t)ret);
        else kp_qlog("access_answer_failed", uid, buf, 0);
        return ret;
    }

    if (selinux_sepolicy_clean_eval_enter() == 0) {
        ret = orig_access_write(file, buf, size);
        selinux_sepolicy_clean_eval_leave();
    } else {
        if (!g_eval_busy_warned) {
            g_eval_busy_warned = true;
            logkfw("selinux_hide: access: redirect slots busy, query refused with -EAGAIN\n");
        }
        return -EAGAIN;
    }

    if (ret > 0)
        ret = kp_patch_response_seqno(buf, ret, KP_AVD_CLEAN_SEQNO);

    if (ret > 0)
        kp_qlog("access_answer", uid, buf, (size_t)ret);

    return ret;
}

/* ---- setprocattr handler ---- */

static bool g_setprocattr_infra_warned;

static int my_setprocattr_new(const char *name, void *value, size_t size)
{
    uid_t uid = current_uid();
    u32 mysid, sid;
    char *str = value;
    char vbuf[96];
    char scratch[KP_CONTEXT_SCRATCH];
    int error;

    /* KernelSU my_setprocattr: apps may only transition to contexts that the
     * CLEAN policy knows; a root-manager context is rejected here, before the
     * stock handler ever consults the patched live policy. */
    if (uid < 10000 || lib_strcmp(name, "current")) goto call_orig;

    /* Stock sequence: the self permission check runs before the context is
     * parsed, and nothing may touch the payload before it.  A denied write has
     * to cost exactly what it costs on stock whether the payload is a valid
     * context or a same-length string that is not; parsing first made a valid
     * context measurably slower than an invalid one (one extra parse ahead of
     * the same denial), which KernelSU a85dcbcf had to fix. */
    mysid = kp_current_sid();
    error = kp_avc_check(mysid, KP_SECCLASS_PROCESS, KP_PROCESS__SETCURRENT);

    if (selinux_hide_query_log != KP_QLOG_OFF) {
        /* After the permission decision, so nothing input-dependent precedes
         * it, and denied writes stay visible: a detector's attr/current probe
         * shows up here as a denied write of a full application context. */
        kp_qlog_str(vbuf, value, size, sizeof(vbuf) - 1);
        logkfi("query setprocattr uid=%u name=%s value=%s%s\n", (unsigned int)uid,
               name ? name : "(null)", vbuf, error ? " (denied)" : "");
    }
    if (error) return error;

    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
        /* The snapshot has to know the context -- that is what rejects a
         * manager context, and here it is the whole decision.  The SID is not
         * used because the stock handler performs the transition: it resolves
         * the context in the live policy itself (registering it there once, as
         * any stock query would) and applies the bounded-transition /
         * DYNTRANSITION / ptrace checks with its own audit trail.  Leaving the
         * live policy out of this path also keeps it free of side effects a
         * clean device would not have: for a denied app the stock handler stops
         * at its own permission check before resolving anything. */
        if (size < sizeof(scratch)) {
            /* Same verdict, without the kstrdup the allocating variant needs:
             * the payload is tokenized in place, so it is copied to the stack
             * instead.  `value` stays untouched for the stock handler below. */
            lib_memcpy(scratch, value, size);
            scratch[size] = '\0';
            error = selinux_sepolicy_context_to_sid_inplace(scratch, (u32)size, &sid);
        } else {
            error = selinux_sepolicy_context_to_sid(value, size, &sid, KP_GFP_KERNEL);
        }
        if (error == -ENOSYS || error == -EOPNOTSUPP) {
            if (!g_setprocattr_infra_warned) {
                g_setprocattr_infra_warned = true;
                logkfw("selinux_hide: snapshot unavailable (%d), app context transitions fall "
                       "back to the stock path\n",
                       error);
            }
            goto call_orig;
        }
        if (error) return error;
    }

call_orig:
    return orig_setprocattr(name, value, size);
}

static int my_setprocattr(const char *name, void *value, size_t size)
{
    if (selinux_hide_is_new_version()) return my_setprocattr_new(name, value, size);
    uid_t uid = current_uid();
    char vbuf[96];

    if (selinux_hide_query_log != KP_QLOG_OFF) {
        kp_qlog_str(vbuf, value, size, sizeof(vbuf) - 1);
        logkfi("query setprocattr uid=%u name=%s value=%s\n", (unsigned int)uid,
               name ? name : "(null)", vbuf);
    }
    if (likely(uid < 10000)) goto call_orig;
    if (lib_strcmp(name, "current")) goto call_orig;
    if (!kfunc(avc_has_perm) || !selinux_has_selinux_state()) goto call_orig;
    if (selinux_sepolicy_clean_eval_enter() == 0) {
        int rc = orig_setprocattr(name, value, size);
        selinux_sepolicy_clean_eval_leave();
        return rc;
    }
    if (!g_setprocattr_busy_warned) {
        g_setprocattr_busy_warned = true;
        logkfw("selinux_hide: setprocattr: redirect slots busy, using the stock path\n");
    }
    return orig_setprocattr(name, value, size);

call_orig:
    return orig_setprocattr(name, value, size);
}
/* ---- /sys/fs/selinux/status (read + mmap) ---- */

static ssize_t my_sel_read_handle_status(struct file *filp, char __user *buffer, size_t count, loff_t *ppos)
{
    uid_t uid = current_uid();

    if (selinux_hide_query_log != KP_QLOG_OFF) {
        logkfi("query status_read uid=%u count=%u pos=%u\n", (unsigned int)uid,
               (unsigned int)count, (unsigned int)(ppos ? *ppos : 0));
    }

    if (selinux_hide_enabled && uid >= 10000) {
        loff_t pos = ppos ? *ppos : 0;
        size_t avail;

        if (!fake_status_vaddr) {
            logkfw("selinux_hide: status read: fake page missing, refusing the read\n");
            return -ENODEV;
        }
        if (pos < 0) return -EINVAL;
        if (!count || pos >= (loff_t)sizeof(fake_status_bytes)) return 0;

        avail = sizeof(fake_status_bytes) - (size_t)pos;
        if (count > avail) count = avail;

        int rc = compat_copy_to_user(buffer, fake_status_bytes + pos, count);
        if (rc != (int)count) return -EFAULT;
        if (ppos) *ppos = pos + (loff_t)count;
        return (ssize_t)count;
    }
    return orig_sel_read_handle_status(filp, buffer, count, ppos);
}

#define KP_VMA_SCAN_WORDS 21

static bool kp_is_kernel_text(unsigned long addr)
{
    static unsigned long text_start, text_end;
    static bool resolved;

    if (!addr) return false;
    if (!resolved) {
        resolved = true;
        if (kallsyms_lookup_name) {
            text_start = kallsyms_lookup_name("_text");
            text_end = kallsyms_lookup_name("_etext");
        }
    }
    if (text_start && text_end) return addr >= text_start && addr < text_end;
    return !is_bad_address((void *)addr);
}

static bool kp_is_kernel_ptr(unsigned long addr)
{
    return addr == 0 || (addr >> 60) == 0xf;
}

static int kp_vma_pgoff(struct vm_area_struct *vma, void *filp, unsigned long *pgoff)
{
    unsigned long *w = (unsigned long *)vma;
    unsigned long want;
    int i;

    if (!vma || is_bad_address((void *)vma) || !filp) return -ENOENT;
    want = kp_untag_addr((unsigned long)filp);

    if (g_vma_vm_pgoff_off >= 0 && g_vma_vm_file_off >= 0) {
        unsigned long file = *(unsigned long *)((unsigned long)vma + g_vma_vm_file_off);
        if (kp_untag_addr(file) == want) {
            *pgoff = *(unsigned long *)((unsigned long)vma + g_vma_vm_pgoff_off);
            return 0;
        }
    }

    for (i = 3; i < KP_VMA_SCAN_WORDS; i++) {
        if (kp_untag_addr(w[i]) != want) continue;
        if (w[i - 2] && !kp_is_kernel_ptr(kp_untag_addr(w[i - 2]))) continue;
        *pgoff = w[i - 1];
        return 0;
    }
    return -ENOENT;
}

static int my_sel_mmap_handle_status(struct file *filp, struct vm_area_struct *vma)
{
    uid_t uid = current_uid();
    unsigned long *vm = (unsigned long *)vma;
    unsigned long start, size, prot, pa, pgoff, flags_off;
    unsigned long kpage = page_size > 0 ? (unsigned long)page_size : KP_PAGE_SIZE;
    int ret;

    kp_qlog_plain("status_mmap", uid);

    if (!selinux_hide_enabled || uid < 10000)
        goto real_page;

    if (!fake_status_vaddr || !kp_remap_pfn_range || !vma || is_bad_address((void *)vma)) {
        logkfw("selinux_hide: status mmap: feature incomplete (page %px remap %llx vma %px), refusing the mapping\n",
               fake_status_vaddr, (unsigned long)kp_remap_pfn_range, vma);
        return -ENODEV;
    }

    start = vm[KP_VMA_VM_START_OFF / sizeof(unsigned long)];
    size = vm[KP_VMA_VM_END_OFF / sizeof(unsigned long)] - start;

    if (kp_vma_pgoff(vma, filp, &pgoff)) {
        logkfw("selinux_hide: status mmap: cannot locate vm_pgoff, refusing the mapping\n");
        return -ENODEV;
    }

    if (pgoff || size != kpage) return -EIO;

    flags_off = kp_vma_vm_flags_off() / sizeof(unsigned long);
    if ((vm[flags_off] & (KP_VM_READ | KP_VM_MAYREAD)) != (KP_VM_READ | KP_VM_MAYREAD)) {
        logkfw("selinux_hide: status mmap: vm_flags slot looks wrong (0x%lx at +%lu), refusing the mapping\n",
               vm[flags_off], flags_off * sizeof(unsigned long));
        return -ENODEV;
    }
    if (vm[flags_off] & KP_VM_WRITE) return -EPERM;
    vm[flags_off] &= ~KP_VM_MAYWRITE;

    prot = vm[kp_vma_page_prot_off() / sizeof(unsigned long)];
    if (!kp_pgprot_plausible(prot)) {
        logkfw("selinux_hide: status mmap: bogus prot=%016lx at vma %px, refusing the mapping\n", prot, vma);
        return -ENODEV;
    }

    if (start & (kpage - 1)) {
        logkfw("selinux_hide: status mmap: unaligned vm_start=%lx\n", start);
        return -EINVAL;
    }

    pa = pgtable_phys_kernel((uintptr_t)fake_status_vaddr);
    if (!pa) {
        logkfw("selinux_hide: status mmap: cannot resolve the fake page PA (vma %px)\n", vma);
        return -ENODEV;
    }

    ret = kp_remap_pfn_range(vma, start, pa >> page_shift, size, prot);
    if (!ret) return 0;

    logkfw("selinux_hide: status mmap: remap_pfn_range failed ret=%d pa=%llx start=%lx\n",
           ret, pa, start);
    return ret;

real_page:
    return orig_sel_mmap_handle_status(filp, vma);
}

/* ---- hook install / uninstall ---- */

static int kp_install_hook(unsigned long func, void *replace, void **backup, const char *name)
{
    if (!func) return -ENOENT;
    hook_err_t err = hook((void *)func, replace, backup);
    if (err != HOOK_NO_ERR) {
        logkfw("selinux_hide: hook %s @ %llx error: %d\n", name, func, err);
        return err;
    }
    if (g_hooked_cnt < (int)(sizeof(g_hooked) / sizeof(g_hooked[0]))) g_hooked[g_hooked_cnt++] = func;
    logkfi("selinux_hide: hooked %s @ %llx\n", name, func);
    return 0;
}

#define KP_MAX_FP_HOOKS 8
static uintptr_t g_fp_slot[KP_MAX_FP_HOOKS];
static void *g_fp_orig[KP_MAX_FP_HOOKS];
static int g_fp_cnt;

static int kp_install_fp_slot(uintptr_t slot, void *replace, void **backup, const char *name)
{
    if (!slot) return -ENOENT;
    fp_hook(slot, replace, backup);
    if (g_fp_cnt < KP_MAX_FP_HOOKS) {
        g_fp_slot[g_fp_cnt] = slot;
        g_fp_orig[g_fp_cnt] = *backup;
        g_fp_cnt++;
    }
    logkfi("selinux_hide: fp-hooked (data) %s @ slot %llx -> %llx\n", name, (unsigned long)slot,
           (unsigned long)replace);
    return 0;
}

static bool kp_slot_is_handler(uintptr_t slot)
{
    if (!slot || is_bad_address((void *)slot)) return false;
    return kp_is_kernel_text(*(unsigned long *)slot);
}

static uintptr_t kp_found_write_op_slot(unsigned long write_op, unsigned long index, const char *name)
{
    sel_write_op_fn *w = (sel_write_op_fn *)write_op;
    if (!write_op || is_bad_address((void *)write_op) || !index) return 0;
    if (is_bad_address(&w[index]) || !kp_slot_is_handler((uintptr_t)&w[index])) return 0;
    logkfw("selinux_hide: %s: write_op[%lu] is an unverified handler slot\n", name, index);
    return (uintptr_t)&w[index];
}

static uintptr_t kp_find_fops_slot(unsigned long ops, unsigned long index, const char *name)
{
    unsigned long *p = (unsigned long *)ops;
    if (!ops || is_bad_address((void *)ops) || !index) return 0;
    if (is_bad_address(&p[index]) || !kp_slot_is_handler((uintptr_t)&p[index])) return 0;
    logkfw("selinux_hide: %s: fops[%lu] is an unverified handler slot\n", name, index);
    return (uintptr_t)&p[index];
}

#define KP_FOPS_SCAN 24

static long kp_fops_find_handler(unsigned long ops, unsigned long handler)
{
    int i;

    if (!ops || is_bad_address((void *)ops) || !handler) return -1;
    for (i = 0; i < KP_FOPS_SCAN; i++) {
        if (((unsigned long *)ops)[i] == handler) return i;
    }
    return -1;
}

static unsigned long kp_fops_shift(void)
{
    if (kver >= VERSION(5, 12, 0)) return 10;
    if (kver >= VERSION(5, 1, 0)) return 11;
    return 10;
}

static unsigned long kp_fops_read_index(long llseek)
{
    return llseek >= 0 ? (unsigned long)llseek + 1 : 0;
}

static unsigned long kp_fops_mmap_index(long llseek)
{
    return llseek >= 0 ? (unsigned long)llseek + kp_fops_shift() : 0;
}

static void kp_uninstall_hooks(void)
{
    for (int i = g_hooked_cnt - 1; i >= 0; i--) {
        if (g_hooked[i]) unhook((void *)g_hooked[i]);
        g_hooked[i] = 0;
    }
    g_hooked_cnt = 0;
    for (int i = g_fp_cnt - 1; i >= 0; i--) {
        if (g_fp_slot[i]) fp_unhook(g_fp_slot[i], g_fp_orig[i]);
        g_fp_slot[i] = 0;
        g_fp_orig[i] = NULL;
    }
    g_fp_cnt = 0;

    g_hooked_context = false;
    g_hooked_access = false;
    g_hooked_status_read = false;
    g_hooked_status_mmap = false;

    orig_context_write = NULL;
    orig_access_write = NULL;
    orig_setprocattr = NULL;
    orig_sel_read_handle_status = NULL;
    orig_sel_mmap_handle_status = NULL;
}

static int selinux_hide_install_hooks(void)
{
    int rc;
    unsigned long write_op, status_ops;
    long llseek_idx;
    unsigned long read_idx, mmap_idx;
    uintptr_t slot;

    fill_fake_status_bytes();
    init_fake_status();

    write_op = lookup_name_with_suffix("write_op");
    status_ops = lookup_name_with_suffix("sel_handle_status_ops");
    llseek_idx = kp_fops_find_handler(status_ops, lookup_name_with_suffix("generic_file_llseek"));
    read_idx = kp_fops_read_index(llseek_idx);
    mmap_idx = kp_fops_mmap_index(llseek_idx);
    log_boot("selinux_hide: write_op=%llx status_ops=%llx idx(llseek=%ld read=%lu mmap=%lu) "
             "ctx=%llx acc=%llx rd=%llx mmap=%llx\n",
             write_op, status_ops, llseek_idx, read_idx, mmap_idx,
             sel_write_context_addr, sel_write_access_addr,
             sel_read_handle_status_addr, sel_mmap_handle_status_addr);

    // https://android.googlesource.com/kernel/common/+/refs/heads/android13-5.10/security/selinux/selinuxfs.c?utm_source=chatgpt.com
    // enum sel_inos 
    if (sel_write_context_addr) {
        rc = kp_install_hook(sel_write_context_addr, (void *)my_write_context, (void **)&orig_context_write,
                             "sel_write_context");
        log_boot("selinux_hide: installed hook for sel_write_context\n");
        if (rc) goto err;
        g_hooked_context = true;
    }else{
        slot = kp_found_write_op_slot(write_op, SEL_WRITE_OP_CONTEXT, "sel_write_context");
        if (slot) {
            kp_install_fp_slot(slot, (void *)my_write_context, (void **)&orig_context_write,"sel_write_context");
            log_boot("selinux_hide: installed fp slot for sel_write_context\n");
            g_hooked_context = true;
        }else{
            log_boot("selinux_hide: failed to find write_op slot for sel_write_context\n");
        }
    }

    if (sel_write_access_addr) {
        rc = kp_install_hook(sel_write_access_addr, (void *)my_write_access, (void **)&orig_access_write,
                             "sel_write_access");
        log_boot("selinux_hide: installed hook for sel_write_access\n");
        if (rc) goto err;
        g_hooked_access = true;
    }else{
        slot = kp_found_write_op_slot(write_op, SEL_WRITE_OP_ACCESS, "sel_write_access");
        if (slot) {
            kp_install_fp_slot(slot, (void *)my_write_access, (void **)&orig_access_write,"sel_write_access");
            log_boot("selinux_hide: installed fp slot for sel_write_access\n");
            g_hooked_access = true;
        }else{
            log_boot("selinux_hide: failed to find write_op slot for sel_write_access\n");
        }
    }

    /* setprocattr is reached through the LSM hook list (no data slot we can
     * address), keep the inline hook. */
    if (selinux_setprocattr_addr) {
        rc = kp_install_hook(selinux_setprocattr_addr, (void *)my_setprocattr, (void **)&orig_setprocattr,
                             "selinux_setprocattr");
        log_boot("selinux_hide: installed hook for selinux_setprocattr\n");
        if (rc) goto err;
    }

    /* status read/mmap: data-pointer hooks in the status file_operations. */

    // https://android.googlesource.com/kernel/common/%2B/d2f7eca60b29006285d57c7035539e33300e89e5/include/linux/fs.h
    // struct file_operations {

    if (sel_read_handle_status_addr){
        rc = kp_install_hook(sel_read_handle_status_addr, (void *)my_sel_read_handle_status,
                             (void **)&orig_sel_read_handle_status, "sel_read_handle_status");
        log_boot("selinux_hide: installed hook for sel_read_handle_status\n");
        if (rc) goto err;
        g_hooked_status_read = true;
    }else{
        if (!read_idx)
            logkfw("selinux_hide: status read slot: sel_handle_status_ops has no anchor for "
                   "generic_file_llseek (CFI jump table?), slot path skipped\n");
        slot = read_idx ? kp_find_fops_slot(status_ops, read_idx, "sel_read_handle_status") : 0;
        if (slot) {
            rc = kp_install_fp_slot(slot, (void *)my_sel_read_handle_status, (void **)&orig_sel_read_handle_status,
                                    "sel_read_handle_status");
            if (rc) goto err;
            log_boot("selinux_hide: installed fops slot for sel_read_handle_status\n");
            g_hooked_status_read = true;
        } else {
            log_boot("selinux_hide: failed to find fops slot for sel_read_handle_status\n");
        }

    }
    if (sel_mmap_handle_status_addr){
        rc = kp_install_hook(sel_mmap_handle_status_addr, (void *)my_sel_mmap_handle_status,
                             (void **)&orig_sel_mmap_handle_status, "sel_mmap_handle_status");
        log_boot("selinux_hide: installed hook for sel_mmap_handle_status\n");
        if (rc) goto err;
        g_hooked_status_mmap = true;
    }else{
        // int (*mmap) (struct file *, struct vm_area_struct *);
        if (!mmap_idx)
            logkfw("selinux_hide: status mmap slot: sel_handle_status_ops has no anchor for "
                   "generic_file_llseek (CFI jump table?), slot path skipped\n");
        slot = mmap_idx ? kp_find_fops_slot(status_ops, mmap_idx, "sel_mmap_handle_status") : 0;
        if (slot) {
            rc = kp_install_fp_slot(slot, (void *)my_sel_mmap_handle_status, (void **)&orig_sel_mmap_handle_status,
                                    "sel_mmap_handle_status");
            if (rc) goto err;
            log_boot("selinux_hide: installed fops slot for sel_mmap_handle_status\n");
            g_hooked_status_mmap = true;
        } else {
            log_boot("selinux_hide: failed to find fops slot for sel_mmap_handle_status\n");
        }
    }
    if (!g_hooked_context || !g_hooked_access) {
        logkfw("selinux_hide: transaction hooks unavailable (context=%d access=%d), not enabling\n",
               g_hooked_context, g_hooked_access);
        rc = -ENOENT;
        goto err;
    }
    if (!fake_status_vaddr || !g_hooked_status_read || !g_hooked_status_mmap) {
        logkfw("selinux_hide: status surface incomplete (page=%d read=%d mmap=%d), not enabling\n",
               fake_status_vaddr != NULL, g_hooked_status_read, g_hooked_status_mmap);
        rc = -ENOENT;
        goto err;
    }
    logkfi("selinux_hide: hooks ready (context=%d access=%d status_read=%d status_mmap=%d setprocattr=%d)\n",
           g_hooked_context, g_hooked_access, g_hooked_status_read, g_hooked_status_mmap,
           selinux_setprocattr_addr != 0);
    return 0;
err:
    kp_uninstall_hooks();
    return rc;
}

/* ---- feature API ---- */

int selinux_hide_enable(void)
{
    int rc;
    #ifdef ANDROID
        if (unlikely(android_is_safe_mode)) return -EPERM;
    #endif
    if (!selinux_hide_is_supported()) {
        logkfw("selinux_hide: kernel < 4.19, feature not supported\n");
        return -EOPNOTSUPP;
    }
    if (selinux_hide_enabled) return 0;

    if (!selinux_sepolicy_backup_ready()) {
        log_boot("selinux_hide: no backup sepolicy available, please save feature and reboot to retry\n");
        return -EAGAIN;
    }

    rc = selinux_hide_install_hooks();
    if (rc) return rc;

    selinux_hide_enabled = true;
    logkfi("selinux_hide: enabled\n");
    return 0;
}

int selinux_hide_disable(void)
{
    if (!selinux_hide_enabled) return 0;

    kp_uninstall_hooks();
    selinux_hide_enabled = false;
    logkfi("selinux_hide: disabled\n");
    return 0;
}

int selinux_hide_is_enabled(void)
{
    return selinux_hide_enabled;
}

long selinux_hide_control(int state)
{
    if (!selinux_hide_is_supported()) return -EOPNOTSUPP;

    /* Query-log switch (see the KP_QLOG_* block above).  Kept out of the
     * enable/disable path so a manager can silence the log without touching
     * the feature state. */
    switch (state) {
    case -2:
        return selinux_hide_query_log;
    case 2:
        selinux_hide_query_log = KP_QLOG_OFF;
        logkfi("query log: off\n");
        return 0;
    case 3:
        selinux_hide_query_log = KP_QLOG_ON;
        logkfi("query log: on (intercepted queries)\n");
        return 0;
    case 4:
        selinux_hide_query_log = KP_QLOG_VERBOSE;
        logkfi("query log: verbose (intercepted queries + ss/ redirects)\n");
        return 0;
    default:
        break;
    }

    if (state < 0) return selinux_hide_enabled ? 1 : 0; /* query: on / off */
    if (state) return selinux_hide_enable();
    return selinux_hide_disable();
}

int selinux_hide_post_fs_data(const char *args)
{
    /* "before" resolves ss/ symbols and snapshots the clean boot policy (the
     * live policy is still untouched here); a bare "post-fs-data" event (no
     * args) from older managers is treated the same.  Hooks are installed at
     * "after", once apd/Magisk have finished their policy reloads. */
    if (lib_strcmp(args, "before") == 0 || args[0] == '\0') {
        log_boot("selinux_hide: post-fs-data before\n");

        struct file *filp = filp_open(KP_SELINUX_HIDE_FILE, KP_O_RDONLY, 0);
        if (!IS_ERR(filp)) {
            filp_close(filp, 0);
            log_boot("selinux_hide: %s exists\n", KP_SELINUX_HIDE_FILE);

            /* Resolve ss/ symbols FIRST: the snapshot below needs the resolved
             * kp_policydb_read/kp_policydb_load_isids. */
            selinux_hide_init();

            /* The live policy is still the untouched boot policy here: deep-copy
             * it so the context/access/setprocattr hooks answer against the clean
             * policy even after apd/Magisk reloads it. */
            int src = selinux_sepolicy_snapshot();
            log_boot("selinux_sepolicy: snapshot rc=%d\n", src);

            if (selinux_sepolicy_snapshot_dirty()) {
                struct file *sf = filp_open(KP_SELINUX_HIDE_STRICT_FILE, KP_O_RDONLY, 0);
                bool strict = !IS_ERR(sf);
                if (strict) {
                    filp_close(sf, 0);
                    logkfw("selinux_hide: %s is present and the snapshot already carries a manager "
                           "domain, refusing to enable\n",
                           KP_SELINUX_HIDE_STRICT_FILE);
                    return 0;
                }
            }

            selinux_hide_approved = true;
        }
    } else if (lib_strcmp(args, "after") == 0) {
        log_boot("selinux_hide: post-fs-data after\n");
        if (selinux_hide_approved) {
            int rc = selinux_hide_enable();
            log_boot("selinux_hide: enable rc: %d\n", rc);
        }
    }
    return 0;
}
int security_context_to_sid_fn(const char *context, int len, u32 *sid, gfp_t gfp)
{
    if (selinux_hide_is_without_sepolicy_state_version()) {
        if (!kfunc(security_context_to_sid)) return -ENOSYS;
        return kfunc(security_context_to_sid)(context, len, sid, gfp);
    } else {
        if (!kfunc(security_context_to_sid_compat) || !kp_selinux_state_addr) return -ENOSYS;
        return kfunc(security_context_to_sid_compat)((void *)kp_selinux_state_addr, context, len, sid, gfp);
    }
}

unsigned long lookup_name_with_suffix(const char *base)
{
    
    /* LLVM LTO mangles static functions to <name>.<n> / <name>.llvm.<hash> /
     * <name>$... .  One kallsyms_on_each_symbol walk covers every form, so there
     * is no need to probe <base>.<0..255> first (kallsyms_on_each_symbol is
     * KernelPatch core infra, always resolved before the builtin features run). */
    unsigned long addr = kallsyms_lookup_name_by_suffix(base);
    if (addr) return addr;
    return 0;
}

int selinux_hide_init(void)
{
    log_boot("selinux_hide: kernel %x, supported: %d\n", kver, selinux_hide_is_supported());

    if (!selinux_hide_is_supported()) return -EOPNOTSUPP;

    /* These symbols are only used by selinux_hide.  Resolve them lazily here
     * instead of adding them to the global misc ksym initialization pass. */
    kfunc(remap_vmalloc_range) =
        (typeof(kfunc(remap_vmalloc_range)))lookup_name_with_suffix("remap_vmalloc_range");
    kp_remap_pfn_range = (remap_pfn_range_fn)lookup_name_with_suffix("remap_pfn_range");
    kfunc(avc_has_perm) = (typeof(kfunc(avc_has_perm)))lookup_name_with_suffix("avc_has_perm");
    kfunc(security_load_policy) =
        (typeof(kfunc(security_load_policy)))lookup_name_with_suffix("security_load_policy");
    kfunc(security_read_policy) =
        (typeof(kfunc(security_read_policy)))lookup_name_with_suffix("security_read_policy");
    kfunc(security_compute_av_user) =
        (typeof(kfunc(security_compute_av_user)))lookup_name_with_suffix("security_compute_av_user");
    kfunc(security_sid_to_context) =
        (typeof(kfunc(security_sid_to_context)))lookup_name_with_suffix("security_sid_to_context");
    if (selinux_hide_is_without_sepolicy_state_version())
        kfunc(security_context_to_sid) =
            (typeof(kfunc(security_context_to_sid)))lookup_name_with_suffix("security_context_to_sid");
    else
        kfunc(security_context_to_sid_compat) =
            (typeof(kfunc(security_context_to_sid_compat)))lookup_name_with_suffix("security_context_to_sid");
    kfunc(security_context_str_to_sid) =
        (typeof(kfunc(security_context_str_to_sid)))lookup_name_with_suffix("security_context_str_to_sid");

    selinux_sepolicy_init();

    kp_resolve_vma_offsets();

    kp_security_cred_getsecid = (security_cred_getsecid_fn)kallsyms_lookup_name("security_cred_getsecid");
    kp_selinux_state_addr = lookup_name_with_suffix("selinux_state");

    sel_write_context_addr = lookup_name_with_suffix("sel_write_context");
    sel_write_access_addr = lookup_name_with_suffix("sel_write_access");
    sel_read_handle_status_addr = lookup_name_with_suffix("sel_read_handle_status");
    sel_mmap_handle_status_addr = lookup_name_with_suffix("sel_mmap_handle_status");
    selinux_setprocattr_addr = lookup_name_with_suffix("selinux_setprocattr");

    log_boot("selinux_hide: sel_write_context: %llx, sel_write_access: %llx, selinux_setprocattr: %llx\n",
             sel_write_context_addr, sel_write_access_addr, selinux_setprocattr_addr);
    log_boot("selinux_hide: sel_read_handle_status: %llx, sel_mmap_handle_status: %llx, cred_getsecid: %llx\n",
             sel_read_handle_status_addr, sel_mmap_handle_status_addr, (unsigned long)kp_security_cred_getsecid);
    return 0;
}
