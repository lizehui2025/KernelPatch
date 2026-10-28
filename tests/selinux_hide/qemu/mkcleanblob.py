#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Make a marker-free copy of a SELinux policy blob for the QEMU fixture.

The fixture needs a policy that the feature's cleanliness scan accepts as the
boot policy, and a "manager reloaded" policy that carries the usual root
markers.  A device dump only gives the latter, so this rewrites the marker
names in place (same length, so the serialized policydb stays valid) and uses
the result as the clean epoch.  This is a test stand-in for a real first-stage
boot policy, not a way to clean a device.

usage: mkcleanblob.py <policy.blob> <clean.blob>
"""
import sys

# (needle, equal-length replacement)
MARKERS = [
    (b"magisk", b"mzgisk"),
    (b"ksu", b"ksz"),
    (b"apatch", b"apatcx"),
    (b"supolicy", b"supolicx"),
    (b"lsposed", b"lsposXd"),
    (b"droidspaces", b"droidspacez"),
    (b"xposed", b"xposXd"),
]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    clean = data
    for needle, repl in MARKERS:
        assert len(needle) == len(repl)
        clean = clean.replace(needle, repl)
    if len(clean) != len(data):
        sys.exit("replacement changed the blob length")
    if clean == data:
        print("warning: no marker was replaced; the blob may already be clean",
              file=sys.stderr)
    open(sys.argv[2], "wb").write(clean)
    print("wrote %s (%d bytes, %d marker replacement(s))"
          % (sys.argv[2], len(clean), sum(data.count(n) for n, _ in MARKERS)))


if __name__ == "__main__":
    main()
