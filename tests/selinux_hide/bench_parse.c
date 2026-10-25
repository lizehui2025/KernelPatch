/* Ad-hoc micro-benchmark for the access fast path (not part of the test suite).
 * Times the old libc calls against the new hand-written ones on this CPU, so the
 * gain can be estimated before it is measured on the phone. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

typedef uint32_t u32;
typedef uint16_t u16;

struct av_decision {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

#include "_fastpath_extract.h"

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#define N 2000000
#define REPS 5

static volatile u32 sink;

int main(void)
{
	const char *q = "u:r:untrusted_app:s0 u:object_r:system_file:s0 6";
	char s[256], t[256], out[96];
	struct av_decision avd = { 0x12345678, 0, 0xffffffff, 1, 0 };
	u16 cls;
	double t0, best_ref, best_fast, best_sn, best_fmt;
	int i, r;

	best_ref = 1e18;
	best_fast = 1e18;
	best_sn = 1e18;
	best_fmt = 1e18;

	for (r = 0; r < REPS; r++) {
		t0 = now_ns();
		for (i = 0; i < N; i++)
			sink += sscanf(q, "%255s %255s %hu", s, t, &cls);
		t0 = (now_ns() - t0) / N;
		if (t0 < best_ref) best_ref = t0;

		t0 = now_ns();
		for (i = 0; i < N; i++)
			sink += kp_parse_access_fast(q, s, t, &cls);
		t0 = (now_ns() - t0) / N;
		if (t0 < best_fast) best_fast = t0;

		t0 = now_ns();
		for (i = 0; i < N; i++)
			sink += snprintf(out, sizeof(out), "%x %x %x %x %u %x",
					 avd.allowed, 0xffffffff, avd.auditallow,
					 avd.auditdeny, avd.seqno, avd.flags);
		t0 = (now_ns() - t0) / N;
		if (t0 < best_sn) best_sn = t0;

		t0 = now_ns();
		for (i = 0; i < N; i++)
			sink += kp_format_avd(out, sizeof(out), &avd);
		t0 = (now_ns() - t0) / N;
		if (t0 < best_fmt) best_fmt = t0;
	}

	printf("parse   sscanf %6.0f ns   fast %6.0f ns   saved %5.0f ns\n",
	       best_ref, best_fast, best_ref - best_fast);
	printf("format  snprintf %6.0f ns fast %6.0f ns   saved %5.0f ns\n",
	       best_sn, best_fmt, best_sn - best_fmt);
	printf("total saved per query: %.0f ns\n",
	       (best_ref - best_fast) + (best_sn - best_fmt));
	return 0;
}
