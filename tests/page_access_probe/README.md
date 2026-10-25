# page_access_probe

Test component for the "page access" check that detects KernelPatch's supercmd
handler. It reproduces the exact call shape from the public writeup and measures
which `argv` entry the kernel faults in.

## What it does

For each of two pathnames (a control and the probe) it:

1. `mmap(3 * PAGE, RW, MAP_SHARED|MAP_ANONYMOUS)` and never writes to it, so all
   three pages start non-resident.
2. Points `argv` at `base + PAGE - 8`, so the array straddles the page boundary:
   `argv[0]` is the last 8 bytes of page 0, `argv[1]` the first 8 bytes of
   page 1.
3. Calls
   `execveat(AT_FDCWD, PATH, argv, (void *)-1, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)`.
4. Measures residency with `mincore()` (per page) and `/proc/self/smaps` (the
   `Rss` a real detector reads), then maps the resident pages back to `argv`
   indices.

Two readers are expected:

- the kernel's own `count(argv)` reads `argv[0]` → faults page 0 (normal, both runs)
- KernelPatch's `handle_supercmd()` reads `argv[1]` → faults page 1 (probe only)

The control run supplies the baseline, so the verdict is a difference, not an
absolute page count. That matters: depending on kernel version and target type,
the syscall can leave page 0 resident for reasons unrelated to any hook.

`envp = (void *)-1` is deliberate. `count(envp)` fails with `-EFAULT` before
`bprm_execve()`, so the target can never execute. Even when `handle_supercmd()`
runs it reads `argv[1]` and returns immediately (it is NULL), so nothing is
rewired. The call is safe to run in-process.

## Build

Build for the same architecture you will run on. The default is **static**,
because a dynamically linked build baked against a glibc loader
(`/lib/ld-linux-aarch64.so.1`) fails under adb shell with
`cannot execute: required file not found` — Android's bionic uses
`/system/bin/linker64` instead.

```
make                 # static, runs on the build host and under adb shell
make STATIC=0        # dynamic (needs the matching glibc loader)
```

Cross-compiling with the NDK also works; keep it static:

```
make CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
adb push page_access_probe /data/local/tmp/
```

## Run

Root is su-allowed by default, so running as root exercises the *handler*, not
the gate — it will always report HOOK. The gate is only tested from an
unprivileged uid. From root you can drop privileges with `-u`:

```
adb shell /data/local/tmp/page_access_probe -u 10000 -n 5    # gate test
adb shell /data/local/tmp/page_access_probe -n 5             # as-is (root: expect HOOK)
```

or equivalently, without `-u` (and if `setpriv` is available):

```
adb shell 'setpriv --reuid=10000 --regid=10000 --clear-groups /data/local/tmp/page_access_probe -n 5'
```

Options: `-p PATH` probe path (default `/system/bin/truncate`), `-c PATH` control
path (default a nonexistent path that cannot match the magic string),
`-f FLAGS` execveat flags (default `0x1100`), `-u UID` drop to UID before
measuring, `-n N` iterations, `-q` one line per iteration, `-h` help.

Exit code: `0` = hook found, `1` = no hook, `2` = error/usage.

### Interpreting the two runs

| run | result | meaning |
|-----|--------|---------|
| `-u 10000` | no hook | uid gate is present and working (fixed tree) |
| `-u 10000` | HOOK | handler reads argv before checking the caller (ungated, e.g. upstream `dev`) |
| root | HOOK | expected: root is su-allowed, so the gate deliberately lets it through |

## Observed results

On an APatch/KernelPatch-enabled host (arm64, 4 KiB pages), with
`argv = base + 0xff8`:

```
uid 0        control  argv[0]=touched argv[1]=-        rss=4K
uid 0        probe    argv[0]=touched argv[1]=TOUCHED  rss=8K   -> HOOK FOUND

uid 10000    control  argv[0]=touched argv[1]=-        rss=4K
uid 10000    probe    argv[0]=touched argv[1]=-        rss=4K   -> no hook
```

Controls that pin down the interpretation:

- `getpid()` on the same mapping: no page resident.
- `write(pipe, base + 0xff8, 8)`, i.e. a plain 8-byte read of `argv[0]`: only
  page 0 resident. So a single fault does not drag in the neighbour page.
- Any non-magic path (regular file, symlink, missing, directory): page 0 only.

So page 0 is the kernel's `count(argv)` and page 1 is the handler's `argv[1]`
read. As root it fires; as an ordinary uid it does not, which is exactly the
`handle_before_execve()` uid gate doing its job. Against an ungated build
(upstream `dev`) the unprivileged run shows `argv[1]=TOUCHED` instead.
