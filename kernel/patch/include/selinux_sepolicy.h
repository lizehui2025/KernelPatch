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

void kp_kernel_str_free(void *p);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* KernelSU-style deep copy of the current clean policy (post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

bool selinux_sepolicy_snapshot_dirty(void);

int selinux_sepolicy_clean_eval_enter(void);
void selinux_sepolicy_clean_eval_leave(void);

/* Query helpers that answer against the deep copy. */
int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);

/*
 * Same lookup, resolved in place.  string_to_context_struct() tokenizes its
 * input with strsep(), so the by-value entry point above has to copy the
 * payload into a fresh buffer first; a caller that already parsed the payload
 * into its own writable stack buffer skips that copy (__kmalloc + memcpy +
 * kfree), which was the largest avoidable cost on the access query path.
 *
 * `scontext` must be writable for scontext_len + 1 bytes, NUL terminated at
 * scontext[scontext_len], and must not be needed intact afterwards.
 */
int selinux_sepolicy_context_to_sid_inplace(char *scontext, u32 scontext_len, u32 *out_sid);
int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp);
void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/*
 * Counters a booted stock kernel reports, both in the mmap'd
 * /sys/fs/selinux/status page and in the seqno carried by access replies
 * (security/selinux/status.c, ss/services.c):
 *
 *   sequence   seqlock progress counter.  A fresh status page starts at 0 and
 *              every update -- policy load, setenforce -- adds 2, so a booted
 *              device always shows an even value (4 on current Android).
 *   policyload seqno of the last policy load, i.e. policy->latest_granting,
 *              which is 1 for the boot-time load.
 *   avd.seqno  avd->seqno = policy->latest_granting (compute_av), so the access
 *              reply has to agree with policyload -- 1/1 -- and not with the
 *              seqlock counter.
 *
 * Kernels that predate the seqlock rewrite leave the page at 0/0.
 */
#define KP_CLEAN_STATUS_SEQUENCE 4
#define KP_CLEAN_STATUS_POLICYLOAD 1
#define KP_AVD_CLEAN_SEQNO KP_CLEAN_STATUS_POLICYLOAD

u32 selinux_sepolicy_clean_seq(void);
u32 selinux_sepolicy_clean_policyload(void);

int selinux_sepolicy_clean_deny_unknown(void);

/* The queries above compute entirely against the deep copy (KernelSU style);
 * no redirect scope is needed or provided any more. */

#endif
