/*
 * attrprobe: paired timing of /proc/self/attr writes, stock vs intercepted.
 *
 * sectime2 measures the selinuxfs query nodes (context/access).  This measures
 * the other hooked surface: proc_pid_attr_write -> security_setprocattr ->
 * selinux_setprocattr, which is where a "SELinux Hide attr PoC" lands.
 *
 * It separates the two costs a hook can add:
 *
 *   fscreate/ok   - the handler is entered but immediately falls through to the
 *                   stock function (name != "current"), so the difference is the
 *                   hook trampoline plus one strcmp, nothing else;
 *   current/*     - the handler does its own work first: a current-sid lookup
 *                   (twice, actually), an avc_has_perm for SETCURRENT, and only
 *                   then either returns the denial or falls through.
 *
 * Comparing the two tells you whether the multiplier comes from the trampoline
 * or from the handler body.
 *
 * Same isolation as sectime2: pinned, optional SCHED_FIFO with a yielding wait,
 * ABBA order per round, per-round median of `reps` samples, getpid fingerprint.
 *
 * usage: attrprobe [-n iters] [-c cpu] [-r reps] [-f]
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
#define NCASE 4
#define MAXIT 4000
#define MAXREP 9

static const char *CASE_NAME[NCASE] = {
	"current/app",    /* valid context, no SETCURRENT permission -> denied  */
	"current/junk",   /* not a context at all                              */
	"current/magisk", /* manager domain the snapshot must not know         */
	"fscreate/ok",    /* name != current: handler must fall straight through */
};

static const char *CASE_PATH[NCASE] = {
	"/proc/self/attr/current",
	"/proc/self/attr/current",
	"/proc/self/attr/current",
	"/proc/self/attr/fscreate",
};

static const char *CASE_VAL[NCASE] = {
	"u:r:untrusted_app:s0",
	"u:r:nosuchdom_zz9:s0",
	"u:r:magisk:s0",
	"u:object_r:app_data_file:s0",
};

struct shared {
	volatile long long seq;
	long long t[2][NCASE][MAXIT];
	long long base[2][MAXIT];
	char scon[2][128];
	char cgroup[2][128];
	int setcon_errno[2];
	int write_errno[2][NCASE];
	int cpu_seen[2];
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
	{
		char *nl = strchr(out, '\n');
		if (nl) *nl = 0;
	}
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

static double med_us(const long long *v, int n)
{
	return (double)median_raw(v, n) / 1000.0;
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
	int fd[NCASE];
	int w, c, k, r;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);

	if (use_rt) {
		struct sched_param sp;

		memset(&sp, 0, sizeof(sp));
		sp.sched_priority = 40;
		if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0)
			S->cpu_seen[id] = -1;
	}

	if (uid >= 0 && setuid(uid) != 0) _exit(2);
	S->setcon_errno[id] = setcon(domain);
	get_current(S->scon[id], sizeof(S->scon[id]));
	get_cgroup(S->cgroup[id], sizeof(S->cgroup[id]));

	for (c = 0; c < NCASE; c++) {
		fd[c] = open(CASE_PATH[c], O_WRONLY);
		S->write_errno[id][c] = 0;
	}

	/* warm up: settle the audit ratelimit and page everything in */
	for (w = 0; w < 50; w++)
		for (c = 0; c < NCASE; c++)
			if (fd[c] >= 0)
				(void)write(fd[c], CASE_VAL[c], strlen(CASE_VAL[c]));

	for (c = 0; c < NCASE; c++) {
		if (fd[c] < 0) continue;
		(void)write(fd[c], CASE_VAL[c], strlen(CASE_VAL[c]));
		S->write_errno[id][c] = errno;
	}

	for (k = 0; k < iters; k++) {
		int slot = ((k & 1) == 0) ? (id == 0 ? 0 : 1) : (id == 0 ? 1 : 0);
		long long want = 2LL * k + slot;

		while (__atomic_load_n(&S->seq, __ATOMIC_ACQUIRE) != want)
			sched_yield();

		for (c = 0; c < NCASE; c++) {
			long long s[MAXREP];

			for (r = 0; r < reps; r++) {
				long long t0;

				if (fd[c] < 0) { s[r] = 0; continue; }
				t0 = now_ns();
				(void)write(fd[c], CASE_VAL[c], strlen(CASE_VAL[c]));
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

	printf("attrprobe: domain=%s iters=%d reps=%d cpu=%d sched=%s\n",
	       domain, iters, reps, cpu, use_rt ? "fifo" : "cfs");

	a = fork();
	if (a == 0) worker(0, -1, domain, iters, reps, use_rt, cpu);
	b = fork();
	if (b == 0) worker(1, APP_UID, domain, iters, reps, use_rt, cpu);
	waitpid(a, &st, 0);
	waitpid(b, &st, 0);

	printf("\n== placement ==\n");
	printf("  stock  : cpu=%d cgroup=%s scon=%s\n", S->cpu_seen[0], S->cgroup[0], S->scon[0]);
	printf("  hooked : cpu=%d cgroup=%s scon=%s\n", S->cpu_seen[1], S->cgroup[1], S->scon[1]);

	printf("\n== what the write returns ==\n");
	for (c = 0; c < NCASE; c++)
		printf("  %-14s stock=%s  hooked=%s\n", CASE_NAME[c],
		       S->write_errno[0][c] ? strerror(S->write_errno[0][c]) : "ok",
		       S->write_errno[1][c] ? strerror(S->write_errno[1][c]) : "ok");

	if (S->setcon_errno[0] || S->setcon_errno[1]) {
		printf("\ncannot run the timing pair: setcon failed\n");
		return 2;
	}

	n = iters;
	printf("\n== paired write latency, median of %d per round, %d rounds ==\n", reps, n);
	printf("%-14s %9s %9s %9s %17s %7s %s\n", "case", "stock us", "hook us", "d us", "95% CI", "ratio", "verdict");
	for (c = 0; c < NCASE; c++) {
		double ma = med_us(S->t[0][c], n), mb = med_us(S->t[1][c], n);
		double lo, hi, d;
		double ratio = ma > 0 ? mb / ma : 0.0;
		int separable, big;
		double pct;

		ci_diff(S->t[1][c], S->t[0][c], n, &lo, &hi, &d);
		pct = ma > 0 ? 100.0 * d / ma : 0.0;
		separable = (lo > 0 || hi < 0);
		big = (pct >= 5.0 || pct <= -5.0);
		printf("%-14s %9.2f %9.2f %+9.2f  [%+6.2f,%+6.2f] %6.2fx %s\n", CASE_NAME[c], ma, mb, d, lo, hi,
		       ratio, (separable && big) ? "DIFFERENT" : "no diff");
	}

	printf("\n== spread of the fscreate delta (trampoline only), p10/p50/p90 ==\n");
	{
		double *d = malloc(sizeof(double) * (size_t)n);

		for (i = 0; i < n; i++) d[i] = (double)(S->t[1][3][i] - S->t[0][3][i]);
		qsort(d, (size_t)n, sizeof(double), cmpd);
		printf("  %+.0f / %+.0f / %+.0f ns\n", d[(int)(n * 0.10)], d[n / 2], d[(int)(n * 0.90)]);
		free(d);
	}

	printf("\n== CPU speed fingerprint (getpid x100 per round) ==\n");
	printf("  stock  : %.0f ns\n", med_us(S->base[0], n) * 10.0);
	printf("  hooked : %.0f ns\n", med_us(S->base[1], n) * 10.0);

	printf("\n");
	return 0;
}
