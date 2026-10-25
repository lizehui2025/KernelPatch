/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * page_access_probe - test component for the "page access" check that detects
 * KernelPatch's supercmd handler (execveat of "/system/bin/truncate").
 *
 * Call shape, mirrored from the public writeup:
 *
 *   base = mmap(3 * PAGE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS)  (never written)
 *   argv = base + PAGE - 8
 *     argv[0] -> page 0
 *     argv[1] -> page 1   ("the second page")
 *   execveat(AT_FDCWD, TARGET, argv, (void *)-1, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)
 *
 * Two userspace readers matter:
 *   - the kernel's own count(argv) reads argv[0]            -> faults page 0
 *   - KernelPatch's handle_supercmd() reads argv[1] first   -> faults page 1
 *
 * So page 0 alone is normal; page 1 is the hook.  The probe measures that with
 * mincore() (per page) and /proc/self/smaps (the Rss a real detector reads),
 * and it runs a control path that cannot match the magic string so the
 * baseline is subtracted instead of assumed.
 *
 * envp = (void *)-1 is deliberate: count(envp) fails with -EFAULT before
 * bprm_execve(), so the target can never actually be executed.  Even when
 * handle_supercmd() is reached it reads argv[1] and returns immediately (it is
 * NULL), so nothing is rewired.  The call is safe to run in-process.
 *
 * The uid gate in handle_before_execve() (this tree) only protects callers that
 * are neither su-allowed nor the trusted manager.  Run the probe as an
 * unprivileged uid to test the gate; running it as root will legitimately
 * trigger the handler.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

#define DEFAULT_PROBE "/system/bin/truncate"
#define DEFAULT_CONTROL "/nonexistent_page_probe_control"
#define DEFAULT_FLAGS (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)
#define NPAGES 3

static size_t page_size;
static int quiet;

struct result {
    unsigned long rss_kb;
    long rc;
    int err;
    int touched[2]; /* argv[0], argv[1] */
};

/* Read the "Rss:" value (kB) of the VMA starting exactly at @start. */
static int smaps_rss_kb(uintptr_t start, unsigned long *rss_kb)
{
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    int in = 0, found = 0;
    unsigned long rss = 0;

    f = fopen("/proc/self/smaps", "r");
    if (!f)
        return -1;

    while (getline(&line, &cap, f) > 0) {
        uintptr_t s, e;

        if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
            if (found)
                break;
            in = (s == start);
            continue;
        }
        if (in && !strncmp(line, "Rss:", 4) && sscanf(line + 4, "%lu", &rss) == 1)
            found = 1;
    }

    free(line);
    fclose(f);

    if (!found)
        return -1;
    *rss_kb = rss;
    return 0;
}

/* argv[i] lives at byte offset off + 8*i; the fault lands on its page. */
static int argv_index_touched(const unsigned char *bits, size_t off, int i)
{
    size_t page = (off + (size_t)i * sizeof(void *)) / page_size;

    return page < NPAGES && (bits[page] & 1);
}

static int measure(const char *target, long flags, size_t off, struct result *res)
{
    size_t len = NPAGES * page_size;
    unsigned char bits[NPAGES] = { 0 };
    void *base;
    long rc;
    int e;

    memset(res, 0, sizeof(*res));

    base = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return -1;
    }

    errno = 0;
    rc = syscall(SYS_execveat, AT_FDCWD, target,
                 (char *)base + off, (void *)-1, flags);
    e = errno;

    if (mincore(base, len, bits) != 0)
        fprintf(stderr, "mincore failed: %s\n", strerror(errno));
    smaps_rss_kb((uintptr_t)base, &res->rss_kb);

    res->rc = rc;
    res->err = e;
    res->touched[0] = argv_index_touched(bits, off, 0);
    res->touched[1] = argv_index_touched(bits, off, 1);

    munmap(base, len);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  -p PATH   probe pathname            (default: %s)\n"
            "  -c PATH   control pathname          (default: %s)\n"
            "  -f FLAGS  execveat flags, base 0    (default: 0x%x)\n"
            "  -u UID    drop to UID first (needs root); use this to test the gate\n"
            "  -n N      iterations                (default: 1)\n"
            "  -q        one line per iteration\n"
            "  -h        this help\n"
            "\n"
            "Detects a supercmd-style execveat handler by watching which argv\n"
            "entry gets faulted on a never-written 3-page mapping.  Root is\n"
            "su-allowed, so only an unprivileged uid tests the uid gate.\n"
            "Exit code 0 = hook found.\n",
            argv0, DEFAULT_PROBE, DEFAULT_CONTROL, DEFAULT_FLAGS);
}

int main(int argc, char **argv)
{
    const char *probe = DEFAULT_PROBE;
    const char *control = DEFAULT_CONTROL;
    long flags = DEFAULT_FLAGS;
    size_t off;
    uid_t drop_uid = (uid_t)-1;
    int iters = 1, i, c, found = 0;

    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        fprintf(stderr, "cannot determine page size\n");
        return 2;
    }
    off = page_size - sizeof(void *);

    while ((c = getopt(argc, argv, "p:c:f:u:n:qh")) != -1) {
        switch (c) {
        case 'p':
            probe = optarg;
            break;
        case 'c':
            control = optarg;
            break;
        case 'f':
            flags = strtol(optarg, NULL, 0);
            break;
        case 'u':
            drop_uid = (uid_t)strtoul(optarg, NULL, 10);
            break;
        case 'n':
            iters = atoi(optarg);
            break;
        case 'q':
            quiet = 1;
            break;
        default:
            usage(argv[0]);
            return c == 'h' ? 0 : 2;
        }
    }
    if (iters <= 0)
        iters = 1;

    if (drop_uid != (uid_t)-1) {
        if (setgroups(0, NULL) != 0 ||
            setgid(drop_uid) != 0 ||
            setuid(drop_uid) != 0) {
            fprintf(stderr, "cannot drop to uid %u: %s\n",
                    (unsigned)drop_uid, strerror(errno));
            return 2;
        }
    }

    if (!quiet) {
        printf("page_access_probe: page size %zu, uid %u, %d iteration(s)\n",
               page_size, (unsigned)getuid(), iters);
        printf("  argv = base + 0x%zx -> argv[0] = page 0, argv[1] = page 1\n", off);
        if (getuid() == 0)
            printf("  note: uid 0 is su-allowed, so this run exercises the handler,\n"
                   "        not the gate.  Use -u UID (e.g. -u 10000) to test the gate.\n");
    }

    for (i = 0; i < iters; i++) {
        struct result ctl, prb;
        int hit;

        if (measure(control, flags, off, &ctl))
            return 2;
        if (measure(probe, flags, off, &prb))
            return 2;

        hit = prb.touched[1] && !ctl.touched[1];
        found |= hit;

        if (quiet) {
            printf("[%d] uid=%u ctl(i0=%d i1=%d rss=%luK rc=%ld) "
                   "probe(i0=%d i1=%d rss=%luK rc=%ld) %s\n",
                   i, (unsigned)getuid(), ctl.touched[0], ctl.touched[1], ctl.rss_kb, ctl.rc,
                   prb.touched[0], prb.touched[1], prb.rss_kb, prb.rc,
                   hit ? "HOOK" : "no-hook");
        } else {
            printf("--- iteration %d ---\n", i);
            printf("  control %-34s rc=%2ld %-22s argv[0]=%s argv[1]=%s rss=%luK\n",
                   control, ctl.rc, ctl.rc < 0 ? strerror(ctl.err) : "ok",
                   ctl.touched[0] ? "touched" : "-",
                   ctl.touched[1] ? "TOUCHED" : "-", ctl.rss_kb);
            printf("  probe   %-34s rc=%2ld %-22s argv[0]=%s argv[1]=%s rss=%luK\n",
                   probe, prb.rc, prb.rc < 0 ? strerror(prb.err) : "ok",
                   prb.touched[0] ? "touched" : "-",
                   prb.touched[1] ? "TOUCHED" : "-", prb.rss_kb);
            printf("  verdict: %s\n", hit
                   ? "argv[1] dereferenced only for the probe path -> supercmd handler present"
                   : "no hook-style argv[1] read");
        }
    }

    if (!quiet)
        printf("result: %s\n", found ? "HOOK FOUND" : "no hook detected");

    return found ? 0 : 1;
}
