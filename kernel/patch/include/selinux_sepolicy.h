/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_SEPOLICY_H_
#define _KP_SELINUX_SEPOLICY_H_

#include <ktypes.h>
#include <selinux_ss.h>

struct selinux_state;
struct av_decision;

/*
 * KernelSU-style deep copy of the clean SELinux policy (see KernelSU's
 * ksu_dup_sepolicy / backup_sepolicy).  At post-fs-data "before" the live
 * policy is still the untouched boot policy; we deep-copy it -- serialize with
 * security_read_policy(), rebuild with policydb_read(), restore the serialized
 * length, load the initial SIDs into our own sidtab -- and answer
 * context/access queries against that copy instead of the (post-reload) live
 * one.
 *
 * The copy owns every inner table (policydb_read rebuilds them all), so no
 * fixup loops are needed and the queries go through the ss/ wrappers with
 * policydb + sidtab passed explicitly -- the same way on every supported
 * kernel, with no fake struct selinux_state.
 *
 * AOSP Android config bits: the policydb_write() hook in
 * patch/android/sepolicy_flags.c ORs android_netlink_route/getneigh into the
 * serialized policy -- the same fix KernelSU applies to the blob's config word
 * by hand.
 */

/* vmalloc/vfree with the *_noprof fallback (GKI 6.12 renamed them). */
void *kp_vmalloc(unsigned long size);
void kp_vfree(const void *addr);

void kp_kernel_str_free(void *p);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* KernelSU-style deep copy of the current clean policy (post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

bool selinux_sepolicy_snapshot_dirty(void);

/* Diagnostic: serialize the live policy and log the root-manager markers it
 * carries ("clean" = none).  Read-only; safe from post-fs-data, from the load
 * hook and from a query path. */
void selinux_sepolicy_probe_live(const char *tag);

/*
 * Last serialized policy blob the load path captured before a root manager
 * patched the live policy, i.e. the same bytes the snapshot is built from.
 *
 * Only exposed once a marker-carrying load has been seen (the capture is then
 * frozen), so the returned buffer can be read without racing a vfree.  NULL
 * before that, or when no clean load was ever captured -- callers must fall
 * back to the live policy in that case.
 *
 * Used for /sys/fs/selinux/policy: an app reading it would otherwise see the
 * manager's extra types (u:r:magisk:s0, ...) straight from the live blob.
 */
const void *selinux_sepolicy_clean_blob(size_t *len);

bool selinux_sepolicy_redirect_active(void);
int selinux_sepolicy_clean_eval_enter(void);
void selinux_sepolicy_clean_eval_leave(void);

/* Query helpers that answer against the deep copy. */
int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp);
void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/* Stock counters for the clean baseline.  The status page is pre-allocated by
 * init_sel_fs() only from 6.10 on; 6.6 - 6.9 create it on the first open,
 * which a clean device reaches after the boot policy load, so their counters
 * start and stay at 0/0.  6.10+ record the load and the enforce switch, i.e.
 * 4/1 (2/1 while still permissive).  policyload is policy->latest_granting
 * (1 for the boot load); avd.seqno is NOT status.policyload and stays 1 on
 * every supporting kernel. */
#define KP_CLEAN_STATUS_SEQUENCE 4
#define KP_CLEAN_STATUS_POLICYLOAD 1

u32 selinux_sepolicy_clean_seq(void);
u32 selinux_sepolicy_clean_policyload(void);

/* avd.seqno is NOT status.policyload: it is policy->latest_granting, which
 * selinux_policy_commit() sets to 1 on the first load and bumps per reload.
 * A clean device has therefore answered seqno=1 from the very first load, on
 * every kernel version -- including <= 6.6, where the status page still reads
 * 0/0 because it did not exist yet when that load committed.  Tying this to
 * clean_policyload() made the access reply answer 0 on those kernels, which
 * stock never does ("avdSeqNo=0" is its own tell). */
#define KP_AVD_CLEAN_SEQNO 1

int selinux_sepolicy_clean_deny_unknown(void);

/* The queries above compute entirely against the deep copy (KernelSU style);
 * no redirect scope is needed or provided any more. */

/* ---- entry points for the 4.9 - 4.18 legacy evaluator ---- */

/* Raw access to the deep copy.  Both return NULL until the snapshot exists. */
void *selinux_sepolicy_policydb(void);
void *selinux_sepolicy_sidtab(void);

/* kmalloc for strings returned to callers that free with kp_kernel_str_free. */
void *selinux_sepolicy_kmalloc(unsigned long size);

/* Context of a SID in the copy (NULL when unknown). */
struct context *selinux_sepolicy_sid_context(u32 sid);

/* Parse a context string against the copy; no live-policy side effects. */
int selinux_sepolicy_parse_context(const char *scontext, u32 scontext_len, struct context *out);

/*
 * Legacy kernels (4.9 - 4.18 without the policydb-argument ss/ helpers) cannot
 * evaluate or render through the kernel's own functions, because those bind the
 * global policydb.  The legacy backend registers its own evaluators here:
 *   av        -- compute a decision for two contexts in the copy
 *   to_string -- render a context of the copy back to a string
 * Once registered, every query helper above routes through them.
 */
void selinux_sepolicy_register_legacy_impl(void (*av)(void *, struct context *, struct context *, u16,
                                                      struct av_decision *),
                                           int (*to_string)(void *, struct context *, char **, u32 *));

#endif
