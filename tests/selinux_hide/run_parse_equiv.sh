#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build and run the differential test for the access-query fast path.
#
# The fast path is extracted verbatim from kernel/patch/common/selinux_hide.c
# into _fastpath_extract.h on every run, so the test always exercises the code
# that actually ships; parse_equiv.c only adds the libc reference and the
# corpus.  Any difference in either the parsed triple or the formatted reply is
# a test failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../kernel/patch/common/selinux_hide.c"
extract="$here/_fastpath_extract.h"

[ -f "$src" ] || { echo "missing $src" >&2; exit 1; }

awk '
  /^static bool kp_is_query_sep/        { grab = 1 }
  /^static ssize_t my_write_access_new/ { grab = 0 }
  grab { print }
' "$src" >"$extract"

for sym in kp_is_query_sep kp_read_query_word kp_parse_access_fast kp_put_hex kp_put_dec kp_format_avd; do
	grep -q "$sym" "$extract" || { echo "extract is missing $sym" >&2; exit 1; }
done

cc=${CC:-cc}
"$cc" -O2 -Wall -Wextra -o "$here/parse_equiv" "$here/parse_equiv.c"
exec "$here/parse_equiv"
