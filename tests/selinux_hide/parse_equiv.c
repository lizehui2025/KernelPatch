// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Differential test for the access-query fast path in
 * kernel/patch/common/selinux_hide.c.
 *
 * The handler answers an app write to /sys/fs/selinux/access, and a detector
 * times that write, so the kernel side replaced sscanf("%255s %255s %hu") and
 * snprintf("%x %x %x %x %u %x") with hand-written code.  "Faster" is only
 * acceptable if the answer is identical, hence this test: it runs the
 * production functions (extracted verbatim from selinux_hide.c by
 * run_parse_equiv.sh, so it cannot drift) against the libc originals over a
 * directed corpus plus randomized inputs, and fails on any difference.
 *
 * The contract checked here is the one selinux_hide.c documents:
 *
 *   kp_parse_access_fast() returns true  => the three values are exactly what
 *                                           sscanf() would have produced;
 *   kp_parse_access_fast() returns false => the handler runs sscanf() itself,
 *                                           so that branch is unchanged by
 *                                           construction.
 *
 * The reference is glibc's vfscanf.  The kernel's own vsscanf shares its
 * behaviour for the shapes the fast path accepts (unsigned decimal with no
 * width cut, plain %s fields), which is exactly why nothing outside that shape
 * is allowed through.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef uint32_t u32;
typedef uint16_t u16;

/* The five fields kp_format_avd() prints; the kernel's struct av_decision
 * carries more, but nothing on this path reads the rest. */
struct av_decision {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

#include "_fastpath_extract.h"

/* ---- reference: the code the fast path replaced ---- */

static int ref_parse(const char *buf, char *scon, char *tcon, u16 *tclass)
{
	return sscanf(buf, "%255s %255s %hu", scon, tcon, tclass) == 3 ? 0 : -1;
}

static void ref_format(char *out, size_t cap, const struct av_decision *avd)
{
	snprintf(out, cap, "%x %x %x %x %u %x", avd->allowed, 0xffffffff,
		 avd->auditallow, avd->auditdeny, avd->seqno, avd->flags);
}

/* ---- harness ---- */

static unsigned long cases, fast_hits, mismatches;
static unsigned long wellformed, wellformed_fallback;

static void check_parse(const char *label, const char *buf)
{
	char fs[256], ft[256], rs[256], rt[256];
	u16 fclass = 0xdead, rclass = 0xbeef;
	bool fast;
	int rc;

	memset(fs, 0, sizeof(fs));
	memset(ft, 0, sizeof(ft));
	memset(rs, 0, sizeof(rs));
	memset(rt, 0, sizeof(rt));

	fast = kp_parse_access_fast(buf, fs, ft, &fclass);
	rc = ref_parse(buf, rs, rt, &rclass);
	cases++;

	if (!strcmp(label, "well-formed")) {
		/* a real query must never pay for the fallback */
		wellformed++;
		if (!fast) wellformed_fallback++;
	}

	if (!fast)
		return; /* falls back to sscanf(); identical by construction */

	fast_hits++;

	if (rc != 0 || strcmp(fs, rs) || strcmp(ft, rt) || fclass != rclass) {
		mismatches++;
		if (mismatches <= 20) {
			fprintf(stderr,
				"MISMATCH [%s] input=\"%s\"\n"
				"  fast: rc=%d scon=\"%s\" tcon=\"%s\" class=%u\n"
				"  ref : rc=%d scon=\"%s\" tcon=\"%s\" class=%u\n",
				label, buf, 0, fs, ft, fclass, rc, rs, rt, rclass);
		}
	}
}

static void check_format(const struct av_decision *avd)
{
	char fast[96], ref[96];
	ssize_t n;

	memset(fast, 0, sizeof(fast));
	memset(ref, 0, sizeof(ref));

	n = kp_format_avd(fast, sizeof(fast), avd);
	ref_format(ref, sizeof(ref), avd);
	cases++;

	if (n != (ssize_t)strlen(ref) || strcmp(fast, ref)) {
		mismatches++;
		if (mismatches <= 20)
			fprintf(stderr,
				"FORMAT MISMATCH\n  fast(%zd)=\"%s\"\n  ref =\"%s\"\n",
				n, fast, ref);
	}
}

/* ---- corpus ---- */

static const char *const directed[] = {
	"u:r:untrusted_app:s0 u:object_r:system_file:s0 6",
	"u:r:untrusted_app_27:s0 u:object_r:app_data_file:s0 6\n",
	"  u:r:a:s0\t\n  u:object_r:b:s0   6  ",
	"u:r:a:s0 u:object_r:b:s0\t6",
	"u:r:a:s0\nu:object_r:b:s0\n6",
	"u:r:a:s0 u:object_r:b:s0 0",
	"u:r:a:s0 u:object_r:b:s0 65535",
	"u:r:a:s0 u:object_r:b:s0 65536",
	"u:r:a:s0 u:object_r:b:s0 99999999999999999999",
	"u:r:a:s0 u:object_r:b:s0 -1",
	"u:r:a:s0 u:object_r:b:s0 +6",
	"u:r:a:s0 u:object_r:b:s0 0000006",
	"u:r:a:s0 u:object_r:b:s0 0x6",
	"u:r:a:s0 u:object_r:b:s0 6x",
	"u:r:a:s0 u:object_r:b:s0",
	"u:r:a:s0 u:object_r:b:s0 ",
	"u:r:a:s0 u:object_r:b:s0 x",
	"u:r:a:s0",
	"u:r:a:s0 ",
	"u:r:a:s0 u:object_r:b:s0 6 extra",
	"",
	" ",
	"\t\n\v\f\r",
	"a b 6",
	"a b 6 ",
	"a  b  6",
	"\va\vb\v6\v",
	"u:object_r:b:s0 u:r:a:s0 1",
	"u:r:su:s0 u:object_r:system_file:s0 6",
	"u:r:magisk:s0 u:object_r:system_file:s0 6",
	"u:r:ksu:s0 u:object_r:system_file:s0 6",
};

/* 255/256-byte fields exercise the width limit, which must fall back. */
static void check_width_boundaries(void)
{
	static char buf[1200];
	int len;

	for (len = 250; len <= 258; len++) {
		memset(buf, 'a', sizeof(buf));
		buf[len] = '\0';
		check_parse("width-scon", buf);

		snprintf(buf, sizeof(buf), "%s b 6", "");
		memset(buf, 'a', (size_t)len);
		buf[len] = ' ';
		memcpy(buf + len + 1, "u:object_r:b:s0 6", 17);
		buf[len + 18] = '\0';
		check_parse("width-scon+rest", buf);
		snprintf(buf, sizeof(buf), "u:r:a:s0 ");
		memset(buf + 9, 'b', (size_t)len);
		buf[9 + len] = ' ';
		memcpy(buf + 10 + len, "6", 2);
		check_parse("width-tcon", buf);
	}
}

static unsigned long rng_state = 0x1234567;

static unsigned long rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static void check_random(void)
{
	static const char alphabet[] =
		"u:r:a:x0_12 9\t\n\v\f\r-+s0o:6e";
	static char buf[600];
	int i;

	for (i = 0; i < 300000; i++) {
		size_t len = rng() % (sizeof(buf) - 1);
		size_t j;

		for (j = 0; j < len; j++)
			buf[j] = alphabet[rng() % (sizeof(alphabet) - 1)];
		buf[len] = '\0';
		check_parse("random", buf);
	}

	/* Well-formed queries: every one must take the fast path. */
	for (i = 0; i < 100000; i++) {
		char con[64];
		size_t n = 0;
		int k, parts = 3 + (int)(rng() % 3);

		con[n++] = 'u';
		con[n++] = ':';
		con[n++] = 'r';
		con[n++] = ':';
		for (k = 0; k < parts; k++)
			con[n++] = (char)('a' + (int)(rng() % 26));
		con[n++] = ':';
		con[n++] = 's';
		con[n++] = '0';
		con[n] = '\0';

		snprintf(buf, sizeof(buf), "%s u:object_r:%s:s0 %u",
			 con, (rng() & 1) ? "system_file" : "app_data_file",
			 (unsigned)(rng() % 65536));
		check_parse("well-formed", buf);
	}
}

static void check_format_corpus(void)
{
	static const u32 values[] = { 0, 1, 0xf, 0x10, 0xff, 0x1000, 0xffff,
				      0x10000, 0xfffff, 0xfffffff, 0xffffffff,
				      0x80000000, 0x12345678, 0xdeadbeef, 2 };
	struct av_decision avd;
	unsigned i, j, k, l;
	int t;

	for (i = 0; i < sizeof(values) / sizeof(values[0]); i++)
		for (j = 0; j < sizeof(values) / sizeof(values[0]); j++)
			for (k = 0; k < sizeof(values) / sizeof(values[0]); k++) {
				memset(&avd, 0, sizeof(avd));
				avd.allowed = values[i];
				avd.auditallow = values[j];
				avd.auditdeny = values[k];
				avd.seqno = values[(i + j) % 15];
				avd.flags = values[(k + j) % 15];
				check_format(&avd);
			}

	for (t = 0; t < 200000; t++) {
		avd.allowed = (u32)rng();
		avd.auditallow = (u32)rng();
		avd.auditdeny = (u32)rng();
		avd.seqno = (u32)rng();
		avd.flags = (u32)rng();
		check_format(&avd);
	}

	/* the tiny-capacity fallback path */
	for (l = 0; l < 64; l++) {
		char out[96];
		memset(out, 0x7f, sizeof(out));
		avd.allowed = 0x1234;
		avd.auditallow = 0;
		avd.auditdeny = 0xffffffff;
		avd.seqno = 1;
		avd.flags = 0;
		if (kp_format_avd(out, l, &avd) < 0) {
			mismatches++;
			fprintf(stderr, "FORMAT negative return at cap=%u\n", l);
		}
	}
}

int main(void)
{
	size_t i;

	for (i = 0; i < sizeof(directed) / sizeof(directed[0]); i++)
		check_parse("directed", directed[i]);

	check_width_boundaries();
	check_random();
	check_format_corpus();

	printf("cases=%lu fast_hits=%lu mismatches=%lu wellformed=%lu wellformed_fallback=%lu\n",
	       cases, fast_hits, mismatches, wellformed, wellformed_fallback);

	if (mismatches || wellformed_fallback) {
		printf("FAIL\n");
		return 1;
	}
	printf("PASS\n");
	return 0;
}
