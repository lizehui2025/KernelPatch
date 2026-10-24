/*
 * sectime: side-channel measurement with the "regular permission check" threat
 * model, plus a deterministic exposure map.
 *
 * Who can actually observe selinuxfs?  Measured, not assumed:
 *   - u:r:untrusted_app:s0 (a normal app)      -> open() is denied by SELinux
 *   - u:r:app_zygote:s0   (AOSP grants query)  -> open() works, queries answered
 *   - u:r:magisk:s0 / su  (privileged)         -> open() works
 *
 * The timing pair is the realistic adversary: two processes in the SAME SELinux
 * domain (so the only difference is the uid gate -> stock vs intercepted path),
 * measuring in lockstep so frequency/thermal drift hits both equally.
 *
 *   worker A: uid 0      + setcon(domain)   -> stock path
 *   worker B: uid 10433  + setcon(domain)   -> intercepted path
 *
 * For each round both measure once, alternating through shared memory.  Output:
 * per-class medians, the paired median difference with a bootstrap 95% CI, and a
 * 5% decision rule.  A positive control (accept vs reject, measured by the same
 * worker) proves the harness can see a real difference at all.
 *
 * usage: sectime [-d domain] [-n iters]        default domain u:r:app_zygote:s0
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

#define APP_UID 10433
#define NCLS 4
#define MAXIT 4000

static const char *CLS_NAME[NCLS] = {"accept", "reject-unknown", "unknown-6char", "hidden-magisk"};
static const char *CLS_CTX[NCLS] = {
    "u:r:untrusted_app:s0",
    "u:r:nosuchdom_zz9:s0",
    "u:r:zzzzzz:s0",        /* same length as u:r:magisk:s0, exists nowhere */
    "u:r:magisk:s0",        /* exists in the live policy, hidden by the snapshot */
};

static const char *PROBE[] = {
    "u:r:untrusted_app:s0", "u:r:app_zygote:s0", "u:r:isolated_app:s0",
    "u:r:sdk_sandbox:s0",   "u:r:magisk:s0",      "u:r:shell:s0",
};
#define NPROBE ((int)(sizeof(PROBE) / sizeof(PROBE[0])))

struct shared {
    volatile int turn;      /* 0 = worker A, 1 = worker B */
    volatile int n;
    volatile int ready_a, ready_b;
    long long t[2][NCLS][MAXIT];
    /* deterministic exposure map: per probe, open errno and query errno */
    int open_errno[2][NPROBE];
    int query_errno[2][NPROBE];
    char query_reply[2][NPROBE][64];
    char scon[2][128];
    int setcon_errno[2];
};

static struct shared *S;

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int setcon(const char *ctx)
{
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) return -errno;
    ssize_t w = write(fd, ctx, strlen(ctx));
    int e = errno;
    close(fd);
    return w < 0 ? -e : 0;
}

static void get_current(char *out, size_t n)
{
    out[0] = 0;
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) return;
    ssize_t r = read(fd, out, n - 1);
    close(fd);
    if (r < 0) { out[0] = 0; return; }
    out[r] = 0;
    char *nl = strchr(out, '\n');
    if (nl) *nl = 0;
}

static int ctx_query(const char *ctx, char *out, size_t outsz)
{
    int fd = open("/sys/fs/selinux/context", O_RDWR);
    if (fd < 0) return -errno;
    ssize_t w = write(fd, ctx, strlen(ctx));
    int e = errno;
    if (w < 0) { close(fd); return -e; }
    ssize_t r = read(fd, out, outsz - 1);
    e = errno;
    close(fd);
    if (r < 0) return -e;
    out[r] = 0;
    return 0;
}

static int cmpll(const void *a, const void *b)
{
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median_ll(const long long *v, int n)
{
    long long *c = malloc(sizeof(long long) * n);
    memcpy(c, v, sizeof(long long) * n);
    qsort(c, n, sizeof(long long), cmpll);
    double m = (n & 1) ? (double)c[n / 2] : ((double)c[n / 2 - 1] + (double)c[n / 2]) / 2.0;
    free(c);
    return m / 1000.0;
}

/* bootstrap CI of the median of the paired differences */
static void ci_diff(const long long *a, const long long *b, int n, double *lo, double *hi, double *med)
{
    double *d = malloc(sizeof(double) * n);
    for (int i = 0; i < n; i++) d[i] = (double)(a[i] - b[i]);
    double *tmp = malloc(sizeof(double) * n);
    memcpy(tmp, d, sizeof(double) * n);
    qsort(tmp, n, sizeof(double), cmpd);
    *med = ((n & 1) ? tmp[n / 2] : (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0) / 1000.0;

    const int B = 800;
    double *ms = malloc(sizeof(double) * B);
    unsigned int seed = 12345u;
    for (int k = 0; k < B; k++) {
        for (int i = 0; i < n; i++) {
            seed = seed * 1103515245u + 12345u;
            tmp[i] = d[(seed >> 8) % (unsigned)n];
        }
        qsort(tmp, n, sizeof(double), cmpd);
        ms[k] = (n & 1) ? tmp[n / 2] : (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0;
    }
    qsort(ms, B, sizeof(double), cmpd);
    *lo = ms[(int)(B * 0.025)] / 1000.0;
    *hi = ms[(int)(B * 0.975)] / 1000.0;
    free(ms);
    free(tmp);
    free(d);
}

static void worker(int id, int uid, const char *domain, int iters)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(7, &set);
    sched_setaffinity(0, sizeof(set), &set);

    if (uid >= 0 && setuid(uid) != 0) _exit(2);
    S->setcon_errno[id] = setcon(domain);
    get_current(S->scon[id], sizeof(S->scon[id]));

    /* deterministic exposure map */
    for (int i = 0; i < NPROBE; i++) {
        char reply[64] = {0};
        int rc = ctx_query(PROBE[i], reply, sizeof(reply));
        S->query_errno[id][i] = rc;
        snprintf(S->query_reply[id][i], sizeof(S->query_reply[id][i]), "%s", reply);
        int fd = open("/sys/fs/selinux/context", O_RDWR);
        S->open_errno[id][i] = fd < 0 ? errno : 0;
        if (fd >= 0) close(fd);
    }

    if (id == 0) S->ready_a = 1; else S->ready_b = 1;
    while (!S->ready_a || !S->ready_b) { /* both workers ready */ }

    for (int k = 0; k < iters; k++) {
        while (__atomic_load_n(&S->turn, __ATOMIC_ACQUIRE) != id) { }
        /* measure every class inside the same turn, so each class gets `iters`
         * paired samples and the drift between turns hits all of them equally */
        for (int c = 0; c < NCLS; c++) {
            char out[64];
            long long t0 = now_ns();
            ctx_query(CLS_CTX[c], out, sizeof(out));
            S->t[id][c][k] = now_ns() - t0;
        }
        __atomic_store_n(&S->turn, 1 - id, __ATOMIC_RELEASE);
    }
    _exit(0);
}

int main(int argc, char **argv)
{
    const char *domain = "u:r:app_zygote:s0";
    int iters = 600;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) domain = argv[++i];
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) iters = atoi(argv[++i]);
    }
    if (iters < 50) iters = 50;
    if (iters > MAXIT) iters = MAXIT;

    S = mmap(NULL, sizeof(*S), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (S == MAP_FAILED) { perror("mmap"); return 2; }
    memset(S, 0, sizeof(*S));
    S->turn = 0;

    printf("sectime: domain=%s iters=%d (A=uid0 stock, B=uid%d intercepted, lockstep)\n\n",
           domain, iters, APP_UID);

    pid_t a = fork();
    if (a == 0) worker(0, -1, domain, iters);
    pid_t b = fork();
    if (b == 0) worker(1, APP_UID, domain, iters);

    int st;
    waitpid(a, &st, 0);
    waitpid(b, &st, 0);

    /* ---------- exposure map (deterministic) ---------- */
    printf("== who can query selinuxfs ==\n");
    printf("%-24s | %-28s | %-28s\n", "context",
           S->setcon_errno[0] == 0 ? S->scon[0] : "(setcon failed)",
           S->setcon_errno[1] == 0 ? S->scon[1] : "(setcon failed)");
    printf("%-24s | %-28s | %-28s\n", "", "uid 0 (stock)", "uid 10433 (intercepted)");
    for (int i = 0; i < NPROBE; i++) {
        char ra[64], rb[64];
        snprintf(ra, sizeof(ra), "%s", S->query_errno[0][i] ? strerror(-S->query_errno[0][i]) : S->query_reply[0][i]);
        snprintf(rb, sizeof(rb), "%s", S->query_errno[1][i] ? strerror(-S->query_errno[1][i]) : S->query_reply[1][i]);
        printf("%-24s | %-28s | %-28s\n", PROBE[i], ra, rb);
    }
    printf("(setcon: stock=%d intercepted=%d)\n\n", S->setcon_errno[0], S->setcon_errno[1]);

    if (S->setcon_errno[0] || S->setcon_errno[1]) {
        printf("cannot run the timing pair: setcon failed\n");
        return 2;
    }

    /* ---------- timing ---------- */
    int n = iters;
    double sens_a = median_ll(S->t[0][0], n) - median_ll(S->t[0][1], n);
    double sens_b = median_ll(S->t[1][0], n) - median_ll(S->t[1][1], n);
    printf("== positive control (same worker, accept - reject) ==\n");
    printf("  stock worker    : %+.2f us\n", sens_a);
    printf("  intercepted one : %+.2f us   <-- the harness must resolve this, or a null\n"
           "                                  result below means nothing\n\n", sens_b);

    printf("== lockstep pair: stock vs intercepted (same SELinux domain) ==\n");
    printf("%-16s %10s %10s %10s %18s %s\n", "class", "stock us", "hook us", "d(med) us",
           "bootstrap 95% CI", "verdict");
    int leaks = 0;
    for (int c = 0; c < NCLS; c++) {
        double ma = median_ll(S->t[0][c], n), mb = median_ll(S->t[1][c], n);
        double lo, hi, d;
        ci_diff(S->t[1][c], S->t[0][c], n, &lo, &hi, &d);
        double pct = ma > 0 ? 100.0 * d / ma : 0.0;
        int separable = (lo > 0 || hi < 0);
        int big = (pct >= 5.0 || pct <= -5.0);
        const char *verdict = (separable && big) ? "DIFFERENT" : "no measurable diff";
        if (separable && big) leaks++;
        printf("%-16s %10.2f %10.2f %+10.2f  [%+6.2f, %+6.2f] %s (%.1f%%)\n", CLS_NAME[c], ma, mb, d, lo, hi,
               verdict, pct);
    }
    /* The existence oracle proper: on the intercepted path, is a hidden name
     * that the live policy knows any different from a same-length name that
     * exists nowhere?  Paired per round inside the same worker, so a difference
     * can only come from the hidden name itself. */
    {
        double lo, hi, d;
        ci_diff(S->t[1][3], S->t[1][2], n, &lo, &hi, &d);
        double base = median_ll(S->t[1][2], n);
        double pct = base > 0 ? 100.0 * d / base : 0.0;
        int separable = (lo > 0 || hi < 0);
        int big = (pct >= 5.0 || pct <= -5.0);
        printf("\n== existence oracle (intercepted path, paired) ==\n");
        printf("  hidden 'u:r:magisk:s0' - 'u:r:zzzzzz:s0' = %+.2f us  CI [%+.2f, %+.2f]  %s (%.1f%%)\n",
               d, lo, hi, (separable && big) ? "SEPARABLE" : "not separable", pct);
        if (separable && big) leaks++;
    }

    printf("\n%d separable finding(s) at the 5%% rule\n", leaks);
    return leaks ? 1 : 0;
}
