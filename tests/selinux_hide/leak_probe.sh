#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Watch kernel memory across a batch of intercepted SELinux queries.
#
# Use it to tell a per-query leak (the numbers grow with the loop, every run)
# from one-off residency (the numbers jump once and then stay flat -- the clean
# policy copy, the sidtab, the fake status page).  Run as root with SELinux Hide
# already enabled; it only samples, it does not change any state.
#
#   sh leak_probe.sh /data/local/tmp/sectime -n 2000
#
# The sidtab line is the LIVE table (/sys/fs/selinux/ss/sidtab_hash_stats); the
# snapshot's own sidtab is private and not readable, so it is judged from the
# kmalloc totals instead.

if [ "$(id -u)" != "0" ]; then
	echo "run as root" >&2
	exit 1
fi

[ $# -gt 0 ] || { echo "usage: $0 <query command> [args...]" >&2; exit 2; }

tmp=${TMPDIR:-/data/local/tmp}
before=$tmp/leak_before.$$
after=$tmp/leak_after.$$

snap() {
	awk '/^kmalloc-/ {printf "slab %-24s active %8s total %8s\n", $1, $2, $3}' /proc/slabinfo | sort
	grep -E '^(Slab|SUnreclaim|VmallocUsed|MemFree|MemAvailable):' /proc/meminfo
	awk '{s += $2} END {printf "VmallocInfoKB: %d\n", s / 1024}' /proc/vmallocinfo
	echo -n "sidtab(live): "
	head -1 /sys/fs/selinux/ss/sidtab_hash_stats 2>/dev/null || echo "unreadable"
}

snap >"$before"

"$@" >/dev/null 2>&1
rc=$?

snap >"$after"

echo "query command rc=$rc"
echo "--- delta (empty = no change) ---"
diff "$before" "$after" || true

rm -f "$before" "$after"
