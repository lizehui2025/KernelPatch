# selinux_hide QEMU fixture

End-to-end test for the built-in `selinux_hide` feature. It boots a
KernelPatch-patched arm64 kernel under `qemu-system-aarch64` with a minimal
initramfs and drives the same lifecycle an Android boot does:

1. mount `proc`, `sys`, `dev` and `selinuxfs`, create
   `/data/adb/ap/selinux_hide` (the feature's control file);
2. load a marker-free policy so the load-capture hook keeps a clean epoch;
3. report the supercmd event `post-fs-data before` -- this builds the
   clean-policy snapshot;
4. load the manager-patched policy (the device dump, with `magisk`/`lsposed`
   type names) as the live policy;
5. report `post-fs-data after` -- this installs the hooks and the fake status
   page;
6. compare the stock view (uid 0, before enable) with the app view
   (uid 10000, after enable);
7. check the two cross-surface invariants and run the timing probes.

The app view is the point of the fixture: on a clean device an app sees the
boot policy, so the fixture asserts that a manager context disappears from
`context`, `access` and `attr/current`, while an ordinary context keeps
working. It also prints the inconsistencies that are still present on the
`fix/selinux-hide-sidechannel` branch:

* `status.policyload` is `0`, while an `access` reply reports `seqno=1`;
  stock reports the same `latest_granting` value on both surfaces. One
  `access` query plus one status read is enough to tell them apart.
* the fake status page is filled once at enable time, so after `setenforce`
  the page an app mapped still shows the old `enforcing`/`sequence`/
  `policyload`, while the real page has moved on.

## Build

Build `kpimg` from this tree, patch a raw arm64 `Image` and build `kptools`:

```sh
cd kernel
make clean
make TARGET_COMPILE=aarch64-none-elf- ANDROID=1 kpimg

cd ../tools
make CC=aarch64-linux-gnu-gcc LDFLAGS="-lz -static"

cd ..
./tools/kptools -p -i Image -k kernel/kpimg -s 12345678 -o Image.patched
```

The superkey must match the one passed to `run-guest.sh` (default
`12345678`); the fixture uses it for the supercmd calls and for the
`SUPERCALL_KLOG` output.

## Policy blob

Take a policy dump from a device:

```sh
adb shell su -c 'cat /sys/fs/selinux/policy' > policy.blob
```

The fixture needs two epochs. `mkcleanblob.py` makes the "clean" one by
renaming the usual root markers in place (same length, so the serialized
`policydb` stays valid). This is a test stand-in for the real first-stage
boot policy, not a tool for cleaning a device. The original dump is loaded
second, standing in for the manager's reload.

## Run

```sh
cd tests/selinux_hide/qemu
./run-guest.sh /path/to/Image.patched /path/to/policy.blob 240
```

The script builds `init`, `sectime2` and `attrprobe` (from the parent
directory), packs the initramfs and runs QEMU. It prints the log from the
fixture's start marker; the full log is left next to the script as
`boot-<image>.log`.

## Expected result (6.6.118-android15 GKI, QEMU TCG)

```
hooks ready (context=1 access=1 status_read=1 status_mmap=1 setprocattr=1)
selinux_hide: enabled

hide-off (stock, live patched policy):
  status: version=1 sequence=4 enforcing=0 policyload=2 deny_unknown=1
  context(magisk) -> success
  access(untrusted_app -> system_file, 6) -> seqno=2
  INVARIANT status.policyload=2 access.seqno=2 -> consistent (stock)

hide-on (uid 10000):
  status: version=1 sequence=0 enforcing=0 policyload=0 deny_unknown=1
  context(untrusted_app) -> success
  context(magisk)        -> EINVAL
  context(nosuchdom)     -> EINVAL
  access(untrusted_app)  -> seqno=1
  access(magisk)         -> EINVAL
  attr/current untrusted_app -> ok
  attr/current magisk        -> EINVAL
  INVARIANT status.policyload=0 access.seqno=1 -> INCONSISTENT (fingerprint)

STEP5 during-enforce: mapped(fake) ok=1 enforcing=0 seq=0 pload=0
                      | real ok=1 enforcing=1 seq=6 pload=2 | setenforce1 rc=0
```

The guest runs permissive, and its PID 1 stays in `u:r:kernel:s0`, so after
the enforcing check `setenforce 0` is denied and console output stops. The
step-5 values are reported through the KernelPatch klog supercall, which is
why they appear as `user log: STEP5 ...` in the kernel log.

## Caveats

* QEMU TCG is only an indicative timing environment. The accept path is
  measurably slower (`attrprobe current/app` around 1.26x in this container),
  but the context numbers move with the host and with the worker speed; use
  a real device for the microsecond-level acceptance in
  `doc/en/selinux-hide-timing.md`.
* `mkcleanblob.py` only removes the marker names the feature scans for. A
  device policy can still resolve `u:r:su:s0`; the fixture logs the snapshot
  as dirty in that case, but (without `/data/adb/ap/selinux_hide_strict`)
  still enables the feature.
* The fixture assumes the policy blob is loadable by the target kernel and
  that the kernel has BTF and the ss/ symbols the feature needs; otherwise
  the hooks or the snapshot are not available and the test reports the
  refusal instead.
