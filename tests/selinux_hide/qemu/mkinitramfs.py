import sys, os, gzip

# usage: mkinitramfs.py <out.cpio.gz> <file>[:mode] ...
def pad4(n):
    return (4 - n % 4) % 4

def entry(name, data, mode, ino):
    name_b = name.encode() + b"\0"
    hdr = b"070701" + b"".join(b"%08x" % f for f in
        [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b), 0])
    out = hdr + name_b
    out += b"\0" * pad4(len(out))
    out += data
    out += b"\0" * pad4(len(data))
    return out

out_p = sys.argv[1]
items = []
ino = 1
for spec in sys.argv[2:]:
    path = spec.split(":", 1)[0]
    name = os.path.basename(path)
    mode = 0o100644
    if name in ("init", "sectime2", "attrprobe"):
        mode = 0o100755
    items.append((name, open(path, "rb").read(), mode))
    ino += 1

buf = b""
for i, (n, d, m) in enumerate(items, 1):
    buf += entry(n, d, m, i)
tr_name = b"TRAILER!!!\0"
tr = b"070701" + b"".join(b"%08x" % f for f in [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(tr_name), 0]) + tr_name
tr += b"\0" * pad4(len(tr))
buf += tr
with gzip.open(out_p, "wb", compresslevel=9) as f:
    f.write(buf)
print("wrote %s (%d bytes uncompressed)" % (out_p, len(buf)))
