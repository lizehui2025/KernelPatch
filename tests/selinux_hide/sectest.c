/*
 * sectest -- deterministic acceptance suite for selinux_hide (see README.md).
 *
 * Every check prints PASS/FAIL with the exact expected and actual value: no
 * medians, no percentages, no "under 5% counts as noise".  The suite is meant
 * to be run on the device as root:
 *
 *   sectest              run everything
 *   sectest -v           also print the raw probe results
 *   ST_SCALE=8 sectest   multiply the stress loops (workers, query storms)
 *
 * Exit code 0 means every check passed apart from the known leaks, which are
 * reported as LEAK and do not fail the run.
 *
 * Layout: the parent stays uid 0 (stock path) and records what a "not hooked"
 * device answers; each child drops to uid 10433 (intercepted path) and records
 * what an app sees.  Only the parent prints, so the output is ordered.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

#define PATH_STATUS "/sys/fs/selinux/status"
#define PATH_ENFORCE "/sys/fs/selinux/enforce"
#define PATH_CONTEXT "/sys/fs/selinux/context"
#define PATH_ACCESS "/sys/fs/selinux/access"
#define PATH_STATS "/sys/fs/selinux/ss/sidtab_hash_stats"
#define PATH_ATTR "/proc/self/attr/current"
#define PATH_SLAB "/proc/slabinfo"

#define APP_UID 10433
#define MAXIT 96

struct item {
    int id;
    int pass;      /* 1 pass, 0 fail, 2 known-leak, -1 info */
    char name[64];
    char detail[192];
};

struct shared {
    /* stock-side (parent, uid 0) reference answers */
    int st_ctx_ok_errno, st_ctx_ok_len;
    char st_ctx_ok_reply[128];
    int st_ctx_bad_errno;
    int st_magisk_errno, st_magisk_len;
    int st_acc_ok, st_acc_errno;
    unsigned st_acc_allowed, st_acc_decided, st_acc_auditallow, st_acc_auditdeny, st_acc_flags, st_acc_seqno;
    int st_magisk_acc_errno;
    int st_zero_errno;

    /* child-side (app) raw values, for the parent's comparisons */
    unsigned app_acc_allowed, app_acc_decided, app_acc_auditallow, app_acc_auditdeny, app_acc_flags, app_acc_seqno;
    int app_acc_errno;
    int app_magisk_acc_errno;
    int app_zero_errno;
    int st_vendor_verdict, app_vendor_verdict;
    char app_vendor_reply[64];
    char st_reply[24][64], app_reply[24][64];
    int st_size_errno[8], app_size_errno[8];
    int idem_ok;
    int st_fresh_verdict;
    char st_fresh_reply[64];
    int fresh_cat;          /* MLS category the child probes with */
    int fresh_hit;          /* category that produced a growth, -1 if none */
    int fresh_probe_ok;
    char fresh_probe_detail[96];

    int n;
    struct item items[MAXIT];
    volatile int child_done;

    /* context parity matrix: app verdict vs stock verdict (0 = accept,
     * otherwise the errno it was rejected with) */
    int mat_st[24], mat_app[24];
};

/* Contexts that a clean device and this device must answer identically.  The
 * manager's own domain is the last entry: it must DIFFER (live accepts, apps
 * must not). */
static const char *MATRIX[] = {
    "u:r:untrusted_app:s0",     "u:r:app_zygote:s0",      "u:r:init:s0",
    "u:r:zygote:s0",            "u:r:shell:s0",           "u:r:priv_app:s0",
    "u:r:sdk_sandbox:s0",       "u:r:isolated_app:s0",    "u:object_r:system_file:s0",
    "u:object_r:msd_daemon:s0", "u:object_r:app_data_file:s0", "u:object_r:vendor_file:s0",
    "u:object_r:rootfs:s0",     "u:object_r:su:s0",       "u:object_r:dex2oat_exec:s0",
    "u:r:ksu:s0",               "u:r:nosuchdom_zz9:s0",   "u:r:magisk:s0",
};
#define NMAT ((int)(sizeof(MATRIX) / sizeof(MATRIX[0])))
#define MATRIX_HIDE_INDEX (NMAT - 1)

static struct shared *S;
static int verbose;
static int scale = 1;   /* ST_SCALE=n multiplies every stress loop */

static void add(int id, int pass, const char *name, const char *fmt, ...)
{
    if (S->n >= MAXIT) return;
    struct item *it = &S->items[S->n++];
    it->id = id;
    it->pass = pass;
    snprintf(it->name, sizeof(it->name), "%s", name);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(it->detail, sizeof(it->detail), fmt, ap);
    va_end(ap);
}

/* ---- primitive probes ---- */

/* /sys/fs/selinux/context: write a context, read back its canonical form. */
static int ctx_query(const char *ctx, char *out, size_t outsz, int *err)
{
    int fd = open(PATH_CONTEXT, O_RDWR);
    if (fd < 0) { if (err) *err = errno; return -1; }
    ssize_t w = write(fd, ctx, strlen(ctx));
    int e = errno;
    if (w < 0) { close(fd); if (err) *err = e; if (out && outsz) out[0] = 0; return -1; }
    ssize_t r = read(fd, out, outsz - 1);
    e = errno;
    close(fd);
    if (r < 0) { if (err) *err = e; return -1; }
    out[r] = 0;
    if (err) *err = 0;
    return (int)r;
}

/* 0 when the context resolves, otherwise the errno it was rejected with. */
static int ctx_verdict(const char *ctx)
{
    char out[128];
    int e = 0;
    if (ctx_query(ctx, out, sizeof(out), &e) >= 0) return 0;
    return e ? e : -1;
}

/* /sys/fs/selinux/access: "scon tcon tclass", read the six-field decision. */
static int acc_query(const char *q, unsigned *allowed, unsigned *decided, unsigned *aa, unsigned *ad,
                     unsigned *seqno, unsigned *flags, int *err)
{
    char buf[256];
    int fd = open(PATH_ACCESS, O_RDWR);
    if (fd < 0) { if (err) *err = errno; return -1; }
    ssize_t w = write(fd, q, strlen(q));
    int e = errno;
    if (w < 0) { close(fd); if (err) *err = e; return -1; }
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    e = errno;
    close(fd);
    if (r < 0) { if (err) *err = e; return -1; }
    buf[r] = 0;
    if (err) *err = 0;
    if (sscanf(buf, "%x %x %x %x %u %x", allowed, decided, aa, ad, seqno, flags) != 6) return -1;
    return 0;
}

static int read_status(unsigned char *buf, int n)
{
    int fd = open(PATH_STATUS, O_RDONLY);
    if (fd < 0) return -1;
    int r = (int)read(fd, buf, n);
    close(fd);
    return r;
}

static unsigned le32(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

static int read_enforce(void)
{
    char c = '?';
    int fd = open(PATH_ENFORCE, O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, &c, 1) != 1) c = '?';
    close(fd);
    return c == '0' ? 0 : 1;
}

static long slab_active(const char *want)
{
    FILE *f = fopen(PATH_SLAB, "r");
    char line[512], name[64];
    long active = -1;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        long a, t;
        if (sscanf(line, "%63s %ld %ld", name, &a, &t) == 3 && strcmp(name, want) == 0) { active = a; break; }
    }
    fclose(f);
    return active;
}

/* ---- child: the app-side (uid 10433) checks ---- */

static void run_app_side(void)
{
    unsigned char st[32];
    int r;
    char reply[128];
    int err;

    /* --- status page --- */
    r = read_status(st, 20);
    if (r != 20) {
        add(1, 0, "status: read 20 bytes", "read=%d errno=%d", r, errno);
    } else {
        unsigned ver = le32(st + 0), seq = le32(st + 4), enf = le32(st + 8), pl = le32(st + 12), du = le32(st + 16);
        int real_enf = read_enforce();
        add(1, ver == 1, "status.version == 1", "expected 1, got %u", ver);
        add(2, seq == 0, "status.sequence == 0", "expected 0, got %u", seq);
        add(3, pl == 0, "status.policyload == 0", "expected 0, got %u", pl);
        add(4, real_enf < 0 || enf == (unsigned)real_enf, "status.enforcing == /enforce",
            "status=%u enforce=%d", enf, real_enf);
        add(5, du == 1, "status.deny_unknown == 1", "expected 1, got %u", du);
        if (verbose) printf("[v] status raw: %u %u %u %u %u\n", ver, seq, enf, pl, du);
    }

    /* --- mmap contract (same errno a stock kernel returns) --- */
    {
        int fd = open(PATH_STATUS, O_RDONLY);
        void *m;
        if (fd < 0) {
            add(6, 0, "mmap: status open", "errno=%d", errno);
        } else {
            long pg = sysconf(_SC_PAGESIZE);
            errno = 0;
            m = mmap(NULL, pg, PROT_READ, MAP_PRIVATE, fd, pg); /* pgoff != 0 */
            add(6, m == MAP_FAILED && errno == EIO, "mmap(pgoff=1) == EIO",
                "ret=%p errno=%d(%s)", m, errno, strerror(errno));
            if (m != MAP_FAILED) munmap(m, pg);

            errno = 0;
            m = mmap(NULL, pg * 2, PROT_READ, MAP_PRIVATE, fd, 0); /* size != one page */
            add(7, m == MAP_FAILED && errno == EIO, "mmap(2 pages) == EIO",
                "ret=%p errno=%d(%s)", m, errno, strerror(errno));
            if (m != MAP_FAILED) munmap(m, pg * 2);

            /* the handler itself must refuse a writable mapping, so the
             * descriptor has to be O_RDWR (with O_RDONLY the VFS answers EACCES
             * before the handler runs) */
            int fdw = open(PATH_STATUS, O_RDWR);
            if (fdw < 0) {
                add(8, -1, "mmap(PROT_WRITE) == EPERM",
                    "not testable: /sys/fs/selinux/status is 0444, so a writable mapping is "
                    "refused by the VFS (errno=%d) before the handler sees it", errno);
            } else {
                errno = 0;
                m = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_SHARED, fdw, 0);
                add(8, m == MAP_FAILED && errno == EPERM, "mmap(PROT_WRITE) == EPERM",
                    "ret=%p errno=%d(%s)", m, errno, strerror(errno));
                if (m != MAP_FAILED) munmap(m, pg);
                close(fdw);
            }

            errno = 0;
            m = mmap(NULL, pg, PROT_READ, MAP_SHARED, fd, 0);
            if (m == MAP_FAILED) {
                add(9, 0, "mmap(PROT_READ) succeeds", "errno=%d(%s)", errno, strerror(errno));
            } else {
                unsigned char rd[32];
                int nr = read_status(rd, 20);
                add(9, nr == 20 && memcmp(m, rd, 20) == 0, "mmap bytes == read() bytes",
                    "read=%d map=%02x%02x%02x%02x...", nr,
                    ((unsigned char *)m)[0], ((unsigned char *)m)[1], ((unsigned char *)m)[2],
                    ((unsigned char *)m)[3]);
                errno = 0;
                int mp = mprotect(m, pg, PROT_WRITE);
                add(10, mp != 0 && errno == EACCES, "mprotect(PROT_WRITE) == EACCES",
                    "ret=%d errno=%d(%s)", mp, errno, strerror(errno));
                munmap(m, pg);
            }
            close(fd);
        }
    }

    /* --- context node answers --- */
    err = 0;
    r = ctx_query("u:r:untrusted_app:s0", reply, sizeof(reply), &err);
    add(11, r > 0 && strcmp(reply, "u:r:untrusted_app:s0") == 0, "context: untrusted_app round-trips",
        "len=%d errno=%d reply='%s'", r, err, reply);

    err = 0;
    r = ctx_query("u:r:nosuchdom_zz9:s0", reply, sizeof(reply), &err);
    add(12, r < 0 && err == EINVAL, "context: unknown domain == EINVAL", "ret=%d errno=%d(%s)", r, err,
        strerror(err));

    err = 0;
    r = ctx_query("u:r:magisk:s0", reply, sizeof(reply), &err);
    add(13, r < 0 && err == EINVAL, "context: magisk hidden == EINVAL", "ret=%d errno=%d(%s)", r, err,
        strerror(err));

    err = 0;
    r = ctx_query("u:r:su:s0", reply, sizeof(reply), &err);
    /* A clean device has no su domain (AOSP only defines the object type), so the
     * expected answer is EINVAL.  This device's snapshot already carries the
     * manager's su domain, so a success here is the known structural leak. */
    add(14, (r < 0 && err == EINVAL) ? 1 : 2, "context: su hidden == EINVAL",
        "expected EINVAL, got ret=%d errno=%d reply='%s'", r, err, reply);

    /* vendor object type: the expectation comes from the live policy (the
     * parent's answer), not from a hardcoded list -- this device has no
     * msd_daemon, so guessing names here only produces false failures */
    err = 0;
    r = ctx_query("u:object_r:vendor_file:s0", reply, sizeof(reply), &err);
    S->app_vendor_verdict = (r > 0) ? 0 : (err ? err : -1);
    snprintf(S->app_vendor_reply, sizeof(S->app_vendor_reply), "%s", reply);

    err = 0;
    r = ctx_query("u:object_r:system_file:s0", reply, sizeof(reply), &err);
    add(16, r > 0 && strcmp(reply, "u:object_r:system_file:s0") == 0, "context: system_file round-trips",
        "len=%d errno=%d reply='%s'", r, err, reply);

    /* zero-length write: the stock handler answers a specific errno; the app
     * path has to answer the same one */
    {
        int fd = open(PATH_CONTEXT, O_RDWR);
        if (fd < 0) {
            add(17, 0, "context: zero-length write matches stock", "open errno=%d", errno);
        } else {
            errno = 0;
            ssize_t w = write(fd, "", 0);
            S->app_zero_errno = (w < 0) ? errno : 0;
            close(fd);
            add(17, S->app_zero_errno == S->st_zero_errno, "context: zero-length write matches stock",
                "app errno=%d stock errno=%d", S->app_zero_errno, S->st_zero_errno);
        }
    }

    /* --- access node: record for the parent's comparison --- */
    {
        int e = 0;
        S->app_acc_errno = 0;
        if (acc_query("u:r:untrusted_app:s0 u:object_r:system_file:s0 6", &S->app_acc_allowed,
                      &S->app_acc_decided, &S->app_acc_auditallow, &S->app_acc_auditdeny,
                      &S->app_acc_seqno, &S->app_acc_flags, &e) != 0)
            S->app_acc_errno = e ? e : -1;
        e = 0;
        S->app_magisk_acc_errno = 0;
        if (acc_query("u:r:magisk:s0 u:object_r:system_file:s0 6", &(unsigned){0}, &(unsigned){0},
                      &(unsigned){0}, &(unsigned){0}, &(unsigned){0}, &(unsigned){0}, &e) != 0)
            S->app_magisk_acc_errno = e ? e : -1;
    }

    /* --- context parity matrix (app side), with the reply bytes --- */
    for (int i = 0; i < NMAT; i++) {
        char out[128];
        int e = 0;
        int r2 = ctx_query(MATRIX[i], out, sizeof(out), &e);
        S->mat_app[i] = (r2 > 0) ? 0 : (e ? e : -1);
        snprintf(S->app_reply[i], sizeof(S->app_reply[i]), "%s", r2 > 0 ? out : "");
    }

    /* --- idempotence: the same query three times returns the same bytes --- */
    {
        char a[128], b[128], c[128];
        int e = 0;
        int r1 = ctx_query("u:r:untrusted_app:s0", a, sizeof(a), &e);
        int r2 = ctx_query("u:r:untrusted_app:s0", b, sizeof(b), &e);
        int r3 = ctx_query("u:r:untrusted_app:s0", c, sizeof(c), &e);
        S->idem_ok = (r1 > 0 && r1 == r2 && r2 == r3 && strcmp(a, b) == 0 && strcmp(b, c) == 0);
    }

    /* --- size parity with the stock handler: same input size, same errno --- */
    {
        static const int sizes[] = {0, 1, 255, 256, 257, 4095, 4096, 8192};
        char junk[8193];
        memset(junk, 'a', sizeof(junk));
        memcpy(junk, "u:r:", 4);
        for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
            int fd = open(PATH_CONTEXT, O_RDWR);
            if (fd < 0) { S->app_size_errno[k] = -1; continue; }
            errno = 0;
            ssize_t w = write(fd, junk, sizes[k]);
            S->app_size_errno[k] = (w < 0) ? errno : 0;
            close(fd);
        }
    }

    /* --- setprocattr: no real transition happens in either case --- */
    {
        int fd = open(PATH_ATTR, O_WRONLY);
        if (fd < 0) {
            add(18, 0, "setprocattr: unknown context == EINVAL", "open errno=%d", errno);
        } else {
            errno = 0;
            ssize_t w = write(fd, "u:r:nosuchdom_zz9:s0", 21);
            add(18, w < 0 && errno == EINVAL, "setprocattr: unknown context == EINVAL",
                "ret=%zd errno=%d(%s)", w, errno, strerror(errno));
            close(fd);
        }
    }
    {
        int fd = open(PATH_ATTR, O_WRONLY);
        if (fd >= 0) {
            errno = 0;
            ssize_t w = write(fd, "u:r:magisk:s0", 13);
            add(71, w < 0 && errno == EINVAL, "setprocattr: manager context refused (EINVAL)",
                "ret=%zd errno=%d(%s)", w, errno, strerror(errno));
            close(fd);
        } else {
            add(71, -1, "setprocattr: manager context refused (EINVAL)", "open errno=%d", errno);
        }
    }
}

/* ---- helpers that need a fresh uid-10433 process ---- */

static pid_t spawn_app_child(void (*fn)(void))
{
    pid_t p = fork();
    if (p == 0) {
        if (setuid(APP_UID) != 0) _exit(3);
        fn();
        _exit(0);
    }
    return p;
}

static void child_reject_queries(void)
{
    char out[128];
    int e;
    for (int i = 0; i < 50; i++) ctx_query("u:r:nosuchdom_zz9:s0", out, sizeof(out), &e);
}

/* A context no boot-time component resolves: same valid type, but a single MLS
 * category the running apps do not use.  If the hook registers accepted contexts
 * in the live sidtab (the stock side effect), the table must grow. */
static void child_fresh_query(void)
{
    char ctx[64], out[128];
    int e;
    snprintf(ctx, sizeof(ctx), "u:r:untrusted_app:s0:c%d", S->fresh_cat);
    ctx_query(ctx, out, sizeof(out), &e);
}

static void child_hidden_query(void)
{
    char out[128];
    int e;
    for (int i = 0; i < 50; i++) ctx_query("u:r:magisk:s0", out, sizeof(out), &e);
}

static void child_hammer(void)
{
    char out[128];
    int e;
    for (int i = 0; i < 2000 * scale; i++) {
        if (ctx_query("u:r:untrusted_app:s0", out, sizeof(out), &e) < 0) _exit(4);
        if (ctx_query("u:r:nosuchdom_zz9:s0", out, sizeof(out), &e) >= 0) _exit(5);
    }
    _exit(0);
}

static void child_mem_storm(void)
{
    char out[128];
    int e;
    for (int i = 0; i < 20000 * scale; i++)
        if (ctx_query("u:r:untrusted_app:s0", out, sizeof(out), &e) < 0) _exit(4);
    _exit(0);
}

static char *read_file_all(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 1 << 20, n = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    ssize_t r;
    while ((r = read(fd, buf + n, cap - n - 1)) > 0) {
        n += (size_t)r;
        if (n + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }
    close(fd);
    buf[n] = 0;
    if (len) *len = n;
    return buf;
}

int main(int argc, char **argv)
{
    verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);
    {
        const char *sc = getenv("ST_SCALE");
        if (sc && atoi(sc) > 1) scale = atoi(sc);
        if (scale > 20) scale = 20;
    }

    S = mmap(NULL, sizeof(*S), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (S == MAP_FAILED) { perror("mmap shared"); return 2; }
    memset(S, 0, sizeof(*S));

    printf("sectest: uid0(parent, stock path) + uid%d(child, intercepted path)\n\n", APP_UID);

    /* ---------- parent: stock reference ---------- */
    {
        char reply[128];
        int e = 0;
        S->st_ctx_ok_len = ctx_query("u:r:untrusted_app:s0", reply, sizeof(reply), &e);
        S->st_ctx_ok_errno = S->st_ctx_ok_len < 0 ? e : 0;
        snprintf(S->st_ctx_ok_reply, sizeof(S->st_ctx_ok_reply), "%s", reply);

        e = 0;
        if (ctx_query("u:r:nosuchdom_zz9:s0", reply, sizeof(reply), &e) < 0) S->st_ctx_bad_errno = e;
        e = 0;
        if (ctx_query("u:r:magisk:s0", reply, sizeof(reply), &e) < 0) S->st_magisk_errno = e;

        int ae = 0;
        S->st_acc_ok = acc_query("u:r:untrusted_app:s0 u:object_r:system_file:s0 6", &S->st_acc_allowed,
                                 &S->st_acc_decided, &S->st_acc_auditallow, &S->st_acc_auditdeny,
                                 &S->st_acc_seqno, &S->st_acc_flags, &ae);
        S->st_acc_errno = ae;

        e = 0;
        if (acc_query("u:r:magisk:s0 u:object_r:system_file:s0 6", &(unsigned){0}, &(unsigned){0},
                      &(unsigned){0}, &(unsigned){0}, &(unsigned){0}, &(unsigned){0}, &e) != 0)
            S->st_magisk_acc_errno = e;

        int fd = open(PATH_CONTEXT, O_RDWR);
        if (fd >= 0) {
            errno = 0;
            ssize_t w = write(fd, "", 0);
            S->st_zero_errno = (w < 0) ? errno : 0;
            close(fd);
        }

        S->st_vendor_verdict = ctx_verdict("u:object_r:vendor_file:s0");

        /* what the live (patched) policy answers -- for contexts a clean device
         * also knows, this is the reference the app path has to match */
        for (int i = 0; i < NMAT; i++) {
            char out[128];
            int e2 = 0;
            int r = ctx_query(MATRIX[i], out, sizeof(out), &e2);
            S->mat_st[i] = (r > 0) ? 0 : (e2 ? e2 : -1);
            snprintf(S->st_reply[i], sizeof(S->st_reply[i]), "%s", r > 0 ? out : "");
        }

        {
            static const int sizes[] = {0, 1, 255, 256, 257, 4095, 4096, 8192};
            char junk[8193];
            memset(junk, 'a', sizeof(junk));
            memcpy(junk, "u:r:", 4);
            for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
                int f2 = open(PATH_CONTEXT, O_RDWR);
                if (f2 < 0) { S->st_size_errno[k] = -1; continue; }
                errno = 0;
                ssize_t w = write(f2, junk, sizes[k]);
                S->st_size_errno[k] = (w < 0) ? errno : 0;
                close(f2);
            }
        }

        if (verbose)
            printf("[v] stock: ctx_ok len=%d errno=%d reply='%s' | ctx_bad errno=%d | magisk errno=%d\n"
                   "[v] stock: access rc=%d errno=%d seqno=%u | magisk access errno=%d | zero errno=%d\n\n",
                   S->st_ctx_ok_len, S->st_ctx_ok_errno, S->st_ctx_ok_reply, S->st_ctx_bad_errno,
                   S->st_magisk_errno, S->st_acc_ok, S->st_acc_errno, S->st_acc_seqno,
                   S->st_magisk_acc_errno, S->st_zero_errno);
    }

    /* ---------- child: app side ---------- */
    {
        pid_t p = spawn_app_child(run_app_side);
        if (p < 0) { perror("fork"); return 2; }
        int status = 0;
        waitpid(p, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            add(19, 0, "app-side child ran", "status=0x%x exit=%d", status,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
    }

    /* ---------- parent: comparisons and the checks that need both sides ---------- */
    add(20, S->app_acc_errno == 0 && S->st_acc_ok == 0 &&
             S->app_acc_allowed == S->st_acc_allowed && S->app_acc_decided == S->st_acc_decided &&
             S->app_acc_auditallow == S->st_acc_auditallow && S->app_acc_auditdeny == S->st_acc_auditdeny &&
             S->app_acc_flags == S->st_acc_flags,
        "access: decision bits == stock",
        "app=%x/%x/%x/%x/%x errno=%d stock=%x/%x/%x/%x/%x", S->app_acc_allowed, S->app_acc_decided,
        S->app_acc_auditallow, S->app_acc_auditdeny, S->app_acc_flags, S->app_acc_errno,
        S->st_acc_allowed, S->st_acc_decided, S->st_acc_auditallow, S->st_acc_auditdeny, S->st_acc_flags);

    add(21, S->app_acc_seqno == 1, "access: app seqno == 1 (clean latest_granting)",
        "expected 1, got %u (stock %u)", S->app_acc_seqno, S->st_acc_seqno);

    add(22, S->app_magisk_acc_errno == EINVAL && S->st_magisk_acc_errno == 0,
        "access: magisk source rejected, stock accepts it",
        "app errno=%d(%s) stock errno=%d", S->app_magisk_acc_errno, strerror(S->app_magisk_acc_errno),
        S->st_magisk_acc_errno);

    add(15, S->app_vendor_verdict == S->st_vendor_verdict &&
             (S->st_vendor_verdict != 0 ||
              strcmp(S->app_vendor_reply, "u:object_r:vendor_file:s0") == 0),
        "context: vendor type matches stock (and round-trips)",
        "app=%s reply='%s' stock=%s",
        S->app_vendor_verdict ? strerror(S->app_vendor_verdict) : "accept", S->app_vendor_reply,
        S->st_vendor_verdict ? strerror(S->st_vendor_verdict) : "accept");

    /* context parity matrix: every entry is an exact verdict comparison against
     * the live policy, except the manager's own domain which has to differ */
    for (int i = 0; i < NMAT; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "matrix: %s", MATRIX[i]);
        if (i == MATRIX_HIDE_INDEX)
            add(30 + i, S->mat_app[i] != 0 && S->mat_st[i] == 0,
                nm, "must differ: app=%s stock=%s",
                S->mat_app[i] ? strerror(S->mat_app[i]) : "accept",
                S->mat_st[i] ? strerror(S->mat_st[i]) : "accept");
        else {
            int reply_same = (S->mat_app[i] != 0 && S->mat_st[i] != 0) ||
                             strcmp(S->app_reply[i], S->st_reply[i]) == 0;
            add(30 + i, S->mat_app[i] == S->mat_st[i] && reply_same,
                nm, "app=%s '%s' stock=%s '%s'",
                S->mat_app[i] ? strerror(S->mat_app[i]) : "accept", S->app_reply[i],
                S->mat_st[i] ? strerror(S->mat_st[i]) : "accept", S->st_reply[i]);
        }
    }

    /* sidtab counter parity: a rejected query must not register anything, an
     * accepted one must register exactly like stock does */
    {
        char *before = read_file_all(PATH_STATS, NULL);
        pid_t p = spawn_app_child(child_reject_queries);
        int status = 0;
        waitpid(p, &status, 0);
        char *after = read_file_all(PATH_STATS, NULL);
        int same = before && after && strcmp(before, after) == 0;
        add(23, same, "sidtab: 50 rejected queries leave the table byte-identical",
            "%s", same ? "identical" : "CHANGED");
        free(before);
        free(after);

        /* A category that an earlier run already registered would show no
         * growth for the same reason a broken registration does, so probe up to
         * 16 candidates and require at least one to grow.  With ~900 free
         * categories this cannot plausibly fail for a working implementation. */
        int changed = 0, tried = 0;
        S->fresh_hit = -1;
        for (int k = 0; k < 16 && !changed; k++) {
            S->fresh_cat = 100 + (int)((getpid() * 37 + time(NULL) * 7 + k * 53) % 900);
            char *b = read_file_all(PATH_STATS, NULL);
            pid_t q = spawn_app_child(child_fresh_query);
            int st2 = 0;
            waitpid(q, &st2, 0);
            char *a = read_file_all(PATH_STATS, NULL);
            changed = b && a && strcmp(b, a) != 0;
            free(b);
            free(a);
            tried++;
            if (changed) S->fresh_hit = S->fresh_cat;
        }
        add(24, changed, "sidtab: one fresh accepted context registers (table grows)",
            "%s after %d candidate(s), category %d", changed ? "grew" : "UNCHANGED",
            tried, S->fresh_hit);

        /* the registered SID has to stay resolvable through the live policy
         * (KernelSU a810677b): ask the same context on the stock path */
        {
            char out[128], want[64];
            int e = 0;
            snprintf(want, sizeof(want), "u:r:untrusted_app:s0:c%d", S->fresh_hit);
            int r = ctx_query(want, out, sizeof(out), &e);
            S->st_fresh_verdict = (r > 0) ? 0 : (e ? e : -1);
            snprintf(S->st_fresh_reply, sizeof(S->st_fresh_reply), "%s", r > 0 ? out : "");
            S->fresh_probe_ok = (S->fresh_hit >= 0 && S->st_fresh_verdict == 0 &&
                                 strcmp(S->st_fresh_reply, want) == 0);
            snprintf(S->fresh_probe_detail, sizeof(S->fresh_probe_detail), "stock=%s reply='%s'",
                     S->st_fresh_verdict ? strerror(S->st_fresh_verdict) : "accept", S->st_fresh_reply);
            add(28, S->fresh_probe_ok, "sidtab: app-registered context resolves on the stock path",
                "%s", S->fresh_probe_detail);
        }

        /* the interesting direction: a name the live policy does know must NOT
         * be registered while being hidden */
        before = read_file_all(PATH_STATS, NULL);
        p = spawn_app_child(child_hidden_query);
        waitpid(p, &status, 0);
        after = read_file_all(PATH_STATS, NULL);
        int same2 = before && after && strcmp(before, after) == 0;
        add(27, same2, "sidtab: 50 hidden-name queries register nothing",
            "%s", same2 ? "byte-identical" : "CHANGED (hidden name leaked into live sidtab)");
        free(before);
        free(after);
    }

    /* input-size parity with the stock handler: for every size the answer code
     * must be the same one a stock device returns */
    {
        static const int sizes[] = {0, 1, 255, 256, 257, 4095, 4096, 8192};
        for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
            char nm[64];
            snprintf(nm, sizeof(nm), "size parity: %d-byte write == stock", sizes[k]);
            add(60 + (int)k, S->app_size_errno[k] == S->st_size_errno[k], nm,
                "app errno=%d stock errno=%d", S->app_size_errno[k], S->st_size_errno[k]);
        }
    }

    add(70, S->idem_ok, "idempotence: same query 3x returns identical bytes",
        "%s", S->idem_ok ? "identical" : "differs");

    /* memory: the canonical string must be freed on every accepted query */
    {
        long b32 = slab_active("kmalloc-32"), b64 = slab_active("kmalloc-64"), b96 = slab_active("kmalloc-96");
        pid_t p = spawn_app_child(child_mem_storm);
        int status = 0;
        waitpid(p, &status, 0);
        long a32 = slab_active("kmalloc-32"), a64 = slab_active("kmalloc-64"), a96 = slab_active("kmalloc-96");
        long d32 = (b32 > 0 && a32 > 0) ? a32 - b32 : -1;
        long d64 = (b64 > 0 && a64 > 0) ? a64 - b64 : -1;
        long d96 = (b96 > 0 && a96 > 0) ? a96 - b96 : -1;
        add(25, b32 > 0 && b64 > 0 && b96 > 0 && d32 < 1000 && d64 < 1000 && d96 < 1000,
            "memory: 20000 accepted queries leak < 1000 objects",
            "delta kmalloc-32=%ld -64=%ld -96=%ld (a leak would be +20000)", d32, d64, d96);
    }

    /* concurrency: eight app workers hammering both paths, all must succeed */
    {
        pid_t kids[32];
        int workers = 8 * scale;
        if (workers > 32) workers = 32;
        int ok = 1;
        for (int i = 0; i < workers; i++) kids[i] = spawn_app_child(child_hammer);
        for (int i = 0; i < workers; i++) {
            int status = 0;
            waitpid(kids[i], &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) ok = 0;
        }
        add(26, ok, "concurrency: workers x 4000 queries all answered",
            "%d workers x %d queries: %s", workers, 4000 * scale,
            ok ? "all clean" : "a worker failed (EAGAIN/ENOSYS?)");
    }

    /* ---------- report ---------- */
    int pass = 0, fail = 0, known = 0;
    printf("%-4s %-52s %s\n", "id", "check", "result");
    printf("---- ---------------------------------------------------- ------------------------------\n");
    for (int i = 0; i < S->n; i++) {
        struct item *it = &S->items[i];
        const char *tag = it->pass == 1 ? "PASS" : it->pass == 2 ? "LEAK" : it->pass == -1 ? "INFO" : "FAIL";
        printf("%-4d %-52s %s\n", it->id, it->name, tag);
        if (it->pass != 1 || verbose) printf("     %s\n", it->detail);
        if (it->pass == 1) pass++;
        else if (it->pass == 2) known++;
        else if (it->pass == 0) fail++;
    }
    printf("\n%d passed, %d failed, %d known leak(s)\n", pass, fail, known);
    return fail ? 1 : 0;
}
