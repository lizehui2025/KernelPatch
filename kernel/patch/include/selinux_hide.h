/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

#include <common.h>

/* Lowest kernel this feature accepts: 4.9.  Kernels below 4.19 are served by
 * the legacy backend in selinux_hide_legacy.c -- no selinux_state, a
 * 5-argument context_struct_compute_av() and a 3-argument
 * context_struct_to_string() -- so the clean policy has to be evaluated
 * without the stateful helpers.  4.19+ keeps the existing main backend, and
 * the two backends never install hooks at the same time. */
#define KP_SELINUX_HIDE_MIN_VERSION VERSION(4, 9, 0)
#define KP_SELINUX_MAIN_VERSION VERSION(4, 19, 0)
#define KP_SELINUX_NEW_VERSION VERSION(5, 0, 0)
#define KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION VERSION(6, 6, 0)
/* Resolve symbols / cache support state at boot. Never installs hooks. */

/* Implemented in selinux_hide.c: true from 4.19 on, where the stateful SELinux
 * layout is guaranteed.  Safe to call from boot-time init. */
int selinux_hide_main_path_supported(void);

/* True when this kernel (4.9 - 4.18) has to be served by the legacy backend. */
int selinux_hide_legacy_required(void);

/* Runtime probe for the selinux_state symbol: decides whether the ss/ helpers
 * take a state argument on pre-4.17 kernels. */
int selinux_hide_runtime_has_state(void);

/* True when a pre-4.19 tree exports selinux_state but nothing can settle the
 * security_read_policy() ABI: both backends would call the ss/ helpers with the
 * wrong argument count, so neither is allowed to run.  BTF settles it, and the
 * manager can force the stateful backend with /data/adb/ap/selinux_hide_main. */
int selinux_hide_state_abi_unverified(void);

/* Whether the ss/ helpers (avc_has_perm, security_read_policy,
 * context_struct_to_string, security_context_to_sid, ...) take a
 * struct selinux_state argument: 4.17+ always, 6.6+ never, and 4.9 - 4.16
 * depends on the vendor backport, so the symbol is probed there.  One rule for
 * every helper, because the backport moved them together. */
static inline bool selinux_hide_ss_takes_state(void)
{
    if (kver >= KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION) return false;
    /* selinux_state itself landed in 4.19; 4.17 and 4.18 are upstream trees
     * without it, so the version alone does not imply the stateful ABI. */
    if (kver >= KP_SELINUX_MAIN_VERSION) return true;
    return selinux_hide_runtime_has_state() != 0;
}

/* ---- legacy backend (4.9 - 4.18) ---- */
int selinux_hide_legacy_init(void);
int selinux_hide_legacy_enable(void);
void selinux_hide_legacy_disable(void);
int selinux_hide_legacy_is_enabled(void);

/* Resolve every symbol the feature uses.  Idempotent; shared by both backends. */
void selinux_hide_resolve_symbols(void);

static inline bool selinux_hide_is_supported(void)
{
    return kver >= KP_SELINUX_HIDE_MIN_VERSION;
}
static inline bool selinux_hide_is_new_version(void)
{
    return kver >= KP_SELINUX_NEW_VERSION;
}
static inline bool selinux_hide_is_without_sepolicy_state_version(void)
{
    return kver >= KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION;
}

int selinux_hide_init(void);

/* Called from report_user_event for the post-fs-data before/after events.
 * args: "before" -> install hooks (also honors the /data/adb/ap file), "after" -> finalize. */
int selinux_hide_post_fs_data(const char *args);

long selinux_hide_control(int state);

/* Current query-log level (see the KP_QLOG_* block in selinux_hide.c); read by
 * selinux_sepolicy.c for its level-2 redirect logging. */
int selinux_hide_query_log_level(void);

/* Whether the feature is currently active. */
int selinux_hide_is_enabled(void);

/* Resolve a (possibly LTO-mangled) static symbol: try the exact name, then a
 * kallsyms_on_each_symbol walk covering <name>.<n> / <name>.llvm.<hash> /
 * <name>$... suffixes. */
unsigned long lookup_name_with_suffix(const char *base);
unsigned long kallsyms_lookup_name_by_suffix(const char *name);
#endif
