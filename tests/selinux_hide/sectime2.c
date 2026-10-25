/*
 * sectime2: paired side-channel probe with explicit isolation and drift
 * reporting.
 *
 * sectime measures the same thing but leaves three sources of noise open, which
 * is why its answer moves between runs:
 *
 *   1. placement - the workers were pinned to cpu7 but still ran under CFS, so
 *      any background task could preempt a measurement window;
 *   2. order - within a round worker A always measured before worker B, so a
 *      monotonic drift (frequency ramp, thermal) always penalised B and showed
 *      up as a positive difference;
 *   3. environment - the absolute numbers move with the machine's state, and
 *      nothing in the output said how fast the CPU was during that run.
 *
 * This version fixes all three:
 *
 *   - both workers are pinned and, with -f, run SCHED_FIFO; the wait for the
 *     peer yields so the peer can actually run (a plain spin under FIFO would
 *     starve it and deadlock);
 *   - the order alternates every round (A B, then B A), so drift cancels;
 *   - each class is sampled `reps` times per round and the round keeps the
 *     median, which drops single-sample tail events;
 *   - every round also times a fixed getpid loop, giving a per-round CPU speed
 *     fingerprint: if the difference scales with it, the run was slower, not
 *     the hook;
 *   - it prints each worker's cgroup and the CPU it actually ran on, so a stray
 *     placement is visible instead of mysterious.
 *
 * usage: sectime2 [-d domain] [-n iters] [-c cpu] [-r reps] [-f]
 *        -f  use SCHED_FIFO (root only, set before setuid)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define APP_UID 10433
#define NCLS 4
#define MAXIT 4000
#define MAXREP 9

static const char *CLS_NAME[NCLS] = { "accept", "reject-unknown", "unknown-6char", "hidden-magisk" };
static const char *CLS_CTX[NCLS] = {
	"u:r:untrusted_app:s0",
	"u:r:nosuchdom_zz9:s0",
	"u:r:zzzzzz:s0",
	"u:r:magisk:s0",
};

static const char *PROBE[] = {
	"u:r:untrusted_app:s0", "u:r:app_zygote:s0", "u:r:isolated_app:s0",
	"u:r:sdk_sandbox:s0",   "u:r:magisk:s0",      "u:r:shell:s0",
};
#define NPROBE ((int)(sizeof(PROBE) / sizeof(PROBE[0])))

struct shared {
	volatile long long seq;          /* advances once per measurement slot */
	long long t[2][NCLS][MAXIT];     /* per-round median, ns */
	long long base[2][MAXIT];        /* per-round getpid fingerprint, ns/100 calls */
	int open_errno[2][NPROBE];
	int query_errno[2][NPROBE];
	char query_reply[2][NPROBE][64];
	char scon[2][128];
	char cgroup[2][128];
	int setcon_errno[2];
	int cpu_seen[2];
	int rep_used;
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
	ssize_t w;
	int e;

	if (fd < 0) return -errno;
	w = write(fd, ctx, strlen(ctx));
	e = errno;
	close(fd);
	return w < 0 ? -e : 0;
}

static void get_current(char *out, size_t n)
{
	int fd = open("/proc/self/attr/current", O_RDONLY);
	ssize_t r;
	char *nl;

	out[0] = 0;
	if (fd < 0) return;
	r = read(fd, out, n - 1);
	close(fd);
	if (r < 0) { out[0] = 0; return; }
	out[r] = 0;
	nl = strchr(out, '\n');
	if (nl) *nl = 0;
}

static void get_cgroup(char *out, size_t n)
{
	int fd = open("/proc/self/cgroup", O_RDONLY);
	ssize_t r;

	out[0] = 0;
	if (fd < 0) return;
	r = read(fd, out, n - 1);
	close(fd);
	if (r <= 0) { out[0] = 0; return; }
	out[r] = 0;
	/* first line is "0::/path" */
	{
		char *nl = strchr(out, '\n');
		if (nl) *nl = 0;
	}
}

static int ctx_query(const char *ctx, char *out, size_t outsz)
{
	int fd = open("/sys/fs/selinux/context", O_RDWR);
	ssize_t w, r;
	int e;

	if (fd < 0) return -errno;
	w = write(fd, ctx, strlen(ctx));
	e = errno;
	if (w < 0) { close(fd); return -e; }
	r = read(fd, out, outsz - 1);
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
	long long *c = malloc(sizeof(long long) * (size_t)n);

	memcpy(c, v, sizeof(long long) * (size_t)n);
	qsort(c, (size_t)n, sizeof(long long), cmpll);
	{
		double m = (n & 1) ? (double)c[n / 2]
				   : ((double)c[n / 2 - 1] + (double)c[n / 2]) / 2.0;
		free(c);
		return m / 1000.0;
	}
}

static long long median_raw(const long long *v, int n)
{
	long long *c = malloc(sizeof(long long) * (size_t)n);
	long long m;

	memcpy(c, v, sizeof(long long) * (size_t)n);
	qsort(c, (size_t)n, sizeof(long long), cmpll);
	m = (n & 1) ? c[n / 2] : (c[n / 2 - 1] + c[n / 2]) / 2;
	free(c);
	return m;
}

static void ci_diff(const long long *a, const long long *b, int n, double *lo, double *hi, double *med)
{
	double *d = malloc(sizeof(double) * (size_t)n);
	double *tmp = malloc(sizeof(double) * (size_t)n);
	const int B = 800;
	double *ms = malloc(sizeof(double) * B);
	unsigned int seed = 12345u;
	int k, i;

	for (i = 0; i < n; i++) d[i] = (double)(a[i] - b[i]);
	memcpy(tmp, d, sizeof(double) * (size_t)n);
	qsort(tmp, (size_t)n, sizeof(double), cmpd);
	*med = ((n & 1) ? tmp[n / 2] : (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0) / 1000.0;

	for (k = 0; k < B; k++) {
		for (i = 0; i < n; i++) {
			seed = seed * 1103515245u + 12345u;
			tmp[i] = d[(seed >> 8) % (unsigned)n];
		}
		qsort(tmp, (size_t)n, sizeof(double), cmpd);
		ms[k] = (n & 1) ? tmp[n / 2] : (tmp[n / 2 - 1] + tmp[n / 2]) / 2.0;
	}
	qsort(ms, B, sizeof(double), cmpd);
	*lo = ms[(int)(B * 0.025)] / 1000.0;
	*hi = ms[(int)(B * 0.975)] / 1000.0;
	free(ms);
	free(tmp);
	free(d);
}

/* fixed workload, used as a per-round CPU speed fingerprint */
static long long bench_getpid(void)
{
	long long t0;
	int i;

	t0 = now_ns();
	for (i = 0; i < 100; i++) (void)getpid();
	return now_ns() - t0;
}

static void worker(int id, int uid, const char *domain, int iters, int reps, int use_rt, int cpu)
{
	cpu_set_t set;
	int w, c, k, r;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);

	if (use_rt) {
		struct sched_param sp;

		memset(&sp, 0, sizeof(sp));
		sp.sched_priority = 40;
		/* set before setuid, which drops CAP_SYS_NICE */
		if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0)
			S->cpu_seen[id] = -1;
	}

	if (uid >= 0 && setuid(uid) != 0) _exit(2);
	S->setcon_errno[id] = setcon(domain);
	get_current(S->scon[id], sizeof(S->scon[id]));
	get_cgroup(S->cgroup[id], sizeof(S->cgroup[id]));

	for (c = 0; c < NPROBE; c++) {
		char reply[64] = {0};
		int rc = ctx_query(PROBE[c], reply, sizeof(reply));
		int fd;

		S->query_errno[id][c] = rc;
		snprintf(S->query_reply[id][c], sizeof(S->query_reply[id][c]), "%s", reply);
		fd = open("/sys/fs/selinux/context", O_RDWR);
		S->open_errno[id][c] = fd < 0 ? errno : 0;
		if (fd >= 0) close(fd);
	}

	/* warm up: page in the buffers, populate the live sidtab, settle the governor */
	for (w = 0; w < 50; w++)
		for (c = 0; c < NCLS; c++) {
			char out[64];

			ctx_query(CLS_CTX[c], out, sizeof(out));
		}

	for (k = 0; k < iters; k++) {
		/* ABBA: even rounds A first, odd rounds B first, so a monotonic
		 * drift inside a round cancels instead of always hitting worker B. */
		int slot = ((k & 1) == 0) ? (id == 0 ? 0 : 1) : (id == 0 ? 1 : 0);
		long long want = 2LL * k + slot;

		while (__atomic_load_n(&S->seq, __ATOMIC_ACQUIRE) != want)
			sched_yield();

		for (c = 0; c < NCLS; c++) {
			long long s[MAXREP];

			for (r = 0; r < reps; r++) {
				char out[64];
				long long t0 = now_ns();

				ctx_query(CLS_CTX[c], out, sizeof(out));
				s[r] = now_ns() - t0;
			}
			S->t[id][c][k] = median_raw(s, reps);
		}
		S->base[id][k] = bench_getpid();
		S->cpu_seen[id] = sched_getcpu();

		__atomic_store_n(&S->seq, want + 1, __ATOMIC_RELEASE);
	}
	_exit(0);
}

int main(int argc, char **argv)
{
	const char *domain = "u:r:app_zygote:s0";
	int iters = 600, reps = 3, cpu = 7, use_rt = 0;
	pid_t a, b;
	int st, i, c, n;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") && i + 1 < argc) domain = argv[++i];
		else if (!strcmp(argv[i], "-n") && i + 1 < argc) iters = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-c") && i + 1 < argc) cpu = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-r") && i + 1 < argc) reps = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-f")) use_rt = 1;
	}
	if (iters < 50) iters = 50;
	if (iters > MAXIT) iters = MAXIT;
	if (reps < 1) reps = 1;
	if (reps > MAXREP) reps = MAXREP;
	if (cpu < 0 || cpu > 31) cpu = 7;

	S = mmap(NULL, sizeof(*S), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (S == MAP_FAILED) { perror("mmap"); return 2; }
	memset(S, 0, sizeof(*S));
	S->rep_used = reps;

	printf("sectime2: domain=%s iters=%d reps=%d cpu=%d sched=%s\n",
	       domain, iters, reps, cpu, use_rt ? "fifo" : "cfs");

	a = fork();
	if (a == 0) worker(0, -1, domain, iters, reps, use_rt, cpu);
	b = fork();
	if (b == 0) worker(1, APP_UID, domain, iters, reps, use_rt, cpu);

	waitpid(a, &st, 0);
	waitpid(b, &st, 0);

	printf("\n== placement (must be the same cpu and the same cgroup) ==\n");
	printf("  stock worker  : cpu=%d cgroup=%s scon=%s\n", S->cpu_seen[0], S->cgroup[0], S->scon[0]);
	printf("  hooked worker : cpu=%d cgroup=%s scon=%s\n", S->cpu_seen[1], S->cgroup[1], S->scon[1]);

	printf("\n== who can query selinuxfs ==\n");
	printf("%-24s | %-28s | %-28s\n", "context", "uid 0 (stock)", "uid 10433 (intercepted)");
	for (i = 0; i < NPROBE; i++) {
		char ra[64], rb[64];

		snprintf(ra, sizeof(ra), "%s", S->query_errno[0][i] ? strerror(-S->query_errno[0][i])
								    : S->query_reply[0][i]);
		snprintf(rb, sizeof(rb), "%s", S->query_errno[1][i] ? strerror(-S->query_errno[1][i])
								    : S->query_reply[1][i]);
		printf("%-24s | %-28s | %-28s\n", PROBE[i], ra, rb);
	}

	if (S->setcon_errno[0] || S->setcon_errno[1]) {
		printf("\ncannot run the timing pair: setcon failed\n");
		return 2;
	}

	n = iters;
	printf("\n== positive control (same worker, accept - reject) ==\n");
	printf("  stock worker    : %+.2f us\n", median_ll(S->t[0][0], n) - median_ll(S->t[0][1], n));
	printf("  intercepted one : %+.2f us\n", median_ll(S->t[1][0], n) - median_ll(S->t[1][1], n));

	printf("\n== lockstep pair, ABBA order, per-round median of %d ==\n", reps);
	printf("%-16s %10s %10s %10s %18s %s\n", "class", "stock us", "hook us", "d(med) us",
	       "bootstrap 95% CI", "verdict");
	for (c = 0; c < NCLS; c++) {
		double ma = median_ll(S->t[0][c], n), mb = median_ll(S->t[1][c], n);
		double lo, hi, d;
		double pct;
		int separable, big;

		ci_diff(S->t[1][c], S->t[0][c], n, &lo, &hi, &d);
		pct = ma > 0 ? 100.0 * d / ma : 0.0;
		separable = (lo > 0 || hi < 0);
		big = (pct >= 5.0 || pct <= -5.0);
		printf("%-16s %10.2f %10.2f %+10.2f  [%+6.2f, %+6.2f] %s (%.1f%%)\n", CLS_NAME[c], ma, mb, d,
		       lo, hi, (separable && big) ? "DIFFERENT" : "no measurable diff", pct);
	}

	/* per-round spread: a wide p10..p90 means the run itself was unstable */
	printf("\n== per-round spread of d(accept), p10/p50/p90 ==\n");
	{
		double *d = malloc(sizeof(double) * (size_t)n);

		for (i = 0; i < n; i++) d[i] = (double)(S->t[1][0][i] - S->t[0][0][i]);
		qsort(d, (size_t)n, sizeof(double), cmpd);
		printf("  %+.0f / %+.0f / %+.0f ns\n", d[(int)(n * 0.10)], d[n / 2], d[(int)(n * 0.90)]);
		free(d);
	}

	printf("\n== CPU speed fingerprint (getpid x100, per-round median) ==\n");
	printf("  stock worker  : %.0f ns\n", median_ll(S->base[0], n) * 1000.0 / 100.0);
	printf("  hooked worker : %.0f ns\n", median_ll(S->base[1], n) * 1000.0 / 100.0);
	{
		/* if the accept difference tracks the fingerprint, the run was slower,
		 * not the hook: report the difference in fingerprint units */
		double fa = median_ll(S->base[0], n), fb = median_ll(S->base[1], n);
		double da = median_ll(S->t[1][0], n) - median_ll(S->t[0][0], n);
		double scale = (fa + fb) / 2.0;

		if (scale > 0)
			printf("  d(accept) / fingerprint = %.4f\n", da / scale);
	}

	printf("\n");
	return 0;
}
