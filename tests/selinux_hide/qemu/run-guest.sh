#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Boot a KernelPatch-patched arm64 Image under QEMU and run the selinux_hide
# end-to-end fixture.
#
#   ./run-guest.sh <Image.patched> <policy.blob> [timeout] [superkey]
#
# <Image.patched> must carry a kpimg built from this tree and be patched with
# the same superkey (default 12345678):
#
#   kptools -p -i Image -k kpimg -s 12345678 -o Image.patched
#
# <policy.blob> is a policy dump from a device (root: cat
# /sys/fs/selinux/policy).  mkcleanblob.py derives a marker-free copy: the
# fixture loads that copy first, so the snapshot is clean, and the original
# afterwards, which stands in for the manager's policy reload.
#
# Needs qemu-system-aarch64, aarch64-linux-gnu-gcc, python3.
set -e

KERNEL=${1:?usage: run-guest.sh <Image.patched> <policy.blob> [timeout] [superkey]}
POLICY=${2:?usage: run-guest.sh <Image.patched> <policy.blob> [timeout] [superkey]}
SECS=${3:-240}
KEY=${4:-12345678}

DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR"

# the initramfs entry must be named policy.blob
if [ "$POLICY" != "policy.blob" ] && [ "$POLICY" != "$DIR/policy.blob" ]; then
    cp "$POLICY" policy.blob
fi
python3 mkcleanblob.py policy.blob clean.blob

CC=${CC:-aarch64-linux-gnu-gcc}
$CC -O2 -static -w -DSUPER_KEY="\"$KEY\"" -o init init.c

FILES="init clean.blob policy.blob"
if [ -f ../sectime2.c ]; then
    $CC -O2 -static -w -o sectime2 ../sectime2.c
    FILES="$FILES sectime2"
fi
if [ -f ../attrprobe.c ]; then
    $CC -O2 -static -w -o attrprobe ../attrprobe.c
    FILES="$FILES attrprobe"
fi
python3 mkinitramfs.py initramfs.cpio.gz $FILES

LOG="$DIR/boot-$(basename "$KERNEL").log"
timeout "$SECS" qemu-system-aarch64 -M virt -cpu max -m 2048 -smp 2 \
    -kernel "$KERNEL" -initrd initramfs.cpio.gz -nographic -no-reboot \
    -append "kpatch=1 console=ttyAMA0 rdinit=/init" > "$LOG" 2>&1 || true

echo "log: $LOG"
sed -n '/selinux_hide sidechannel test start/,$p' "$LOG" | tr -d '\r'
