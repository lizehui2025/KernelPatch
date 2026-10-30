/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_KBTF_H_
#define _KP_KBTF_H_

#include <ktypes.h>

int kp_btf_available(void);
long kp_btf_type_size(const char *name);
long kp_btf_member_offset(const char *struct_name, const char *member);
const void *kp_btf_raw(long *size_out);

// Low-level type-graph walk (arbitrary depth, caller-managed cycle handling).
int kp_btf_find_type(const char *name);
int kp_btf_type_info(int type_id, const char **name_out, int *kind_out, long *size_out);
int kp_btf_member(int type_id, int idx, const char **name_out, int *type_id_out, long *bit_offset_out);
int kp_btf_skip_mod(int type_id);

// Parameter count of a kernel function's BTF prototype, or -1 when the kernel
// carries no BTF (or no FUNC record for that name).  Lets a caller settle an
// ABI question the kernel version cannot answer, e.g. whether a pre-4.19
// vendor backport turned security_read_policy() into the 3-argument form.
int kp_btf_func_args(const char *name);

#endif
