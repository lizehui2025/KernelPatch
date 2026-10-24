/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_SEPOLICY_H_
#define _KP_SELINUX_SEPOLICY_H_

#include <ktypes.h>

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

/* Free a string the kernel allocated for a context (context_struct_to_string()
 * or the sidtab sid2str copy).  Needed because kfunc(kfree) is never resolved:
 * free is not in the misc ksym match table. */
void kp_kernel_str_free(void *p);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* KernelSU-style deep copy of the current clean policy (post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

/* True when the snapshot already resolves a manager domain (u:r:su:s0,
 * u:r:ksu:s0, ...): the captured blob was patched before it was taken, so the
 * feature cannot hide those names and the manager gets a warning instead. */
bool selinux_sepolicy_snapshot_dirty(void);

/* Redirect scope used by the < 5.0 path: while a task is inside it, the
 * string_to_context_struct / context_struct_compute_av hooks swap the live
 * policydb for the clean snapshot.  Enter returns 0 on success, -EAGAIN when
 * another task already holds the slot. */
int selinux_sepolicy_clean_eval_enter(void);
void selinux_sepolicy_clean_eval_leave(void);

/* Query helpers that answer against the deep copy. */
int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp);
void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/* Seqlock counter the fake /sys/fs/selinux/status page reports.  It is not the
 * same value as the access response's seqno: status.sequence is the seqlock
 * counter (even when idle, +2 per update) while status.policyload and the
 * access response carry the policy's latest_granting.  Conflating the two is
 * itself a detectable inconsistency. */
u32 selinux_sepolicy_clean_seq(void);
/* latest_granting a clean device reports after its single boot policy load;
 * used as the access response's seqno. */
#define KP_AVD_CLEAN_SEQNO 1

/* deny_unknown of the clean policy (!allow_unknown).  The status page has to
 * agree with what this feature answers for an unknown class, otherwise the two
 * views contradict each other on an allow_unknown policy. */
int selinux_sepolicy_clean_deny_unknown(void);

/* The queries above compute entirely against the deep copy (KernelSU style);
 * no redirect scope is needed or provided any more. */

#endif
