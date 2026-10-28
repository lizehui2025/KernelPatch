/* QEMU guest init for the selinux_hide end-to-end fixture.
 *
 * Sequence (mirrors an Android boot):
 *   1. load a marker-free policy  -> the load-capture hook keeps it
 *   2. supercmd "event post-fs-data before" -> deep copy of the clean policy
 *   3. load the manager-patched policy (magisk/lsposed present) -> live policy
 *   4. supercmd "event post-fs-data after"  -> install hooks, fake status page
 *
 * The supercmd path is /system/bin/truncate (KernelPatch's SUPERCMD) and the
 * key below must match the superkey the Image was patched with:
 *   kptools -p -i Image -k kpimg -s 12345678 -o Image.patched
 *
 * Then compare the stock view (uid 0, before enable) with the app view
 * (uid 10000, after enable) and print the cross-surface invariants:
 *   - status.policyload vs the seqno field of an access reply
 *   - the fake status page vs the real one after setenforce
 *
 * sectime2 and attrprobe are run when they are present in the initramfs; the
 * run script builds them from ../../.. (this directory's parent) if possible.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/klog.h>

#define POLICY_CLEAN "/clean.blob"
#define POLICY_ROOTED "/policy.blob"
#define SUPERCMD_PATH "/system/bin/truncate"
#ifndef SUPER_KEY
#define SUPER_KEY "12345678"
#endif
#define APP_UID 10000

#define SC_NR 45
#define SC_SUB_FEATURE 0x1046
#define SC_SUB_HELLO 0x1000

struct kstatus {
    unsigned int version, sequence, enforcing, policyload, deny_unknown;
};

static long sc_call(unsigned int sub, const char *name, int state)
{
    long cmd = ((long)0x000d09 << 32) | (0x1158L << 16) | sub;
    if (name)
        return syscall(SC_NR, SUPER_KEY, cmd, name, state);
    return syscall(SC_NR, SUPER_KEY, cmd);
}

static void klog_msg(const char *fmt, ...)
{
    char buf[512];
    va_list va;
    long cmd = ((long)0x000d09 << 32) | (0x1158L << 16) | 0x1004; /* SUPERCALL_KLOG */

    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    syscall(SC_NR, SUPER_KEY, cmd, buf);
}

static int trigger_event(const char *event, const char *args)
{
    pid_t p = fork();
    int st = 0;

    if (p == 0) {
        char *argv[] = { (char *)"kp", (char *)SUPER_KEY, (char *)"event",
                         (char *)event, (char *)args, NULL };
        alarm(10);
        execve(SUPERCMD_PATH, argv, NULL);
        _exit(0);
    }
    if (p < 0) {
        printf("event %s/%s: fork failed: %s\n", event, args, strerror(errno));
        return -1;
    }
    waitpid(p, &st, 0);
    printf("event %s/%s: child status 0x%x\n", event, args, st);
    return 0;
}

static int read_status(struct kstatus *s)
{
    unsigned int v[5] = { 0 };
    int fd = open("/sys/fs/selinux/status", O_RDONLY);
    ssize_t r;

    if (fd < 0) return -errno;
    r = read(fd, v, sizeof(v));
    close(fd);
    if (r != (ssize_t)sizeof(v)) return -EIO;
    s->version = v[0];
    s->sequence = v[1];
    s->enforcing = v[2];
    s->policyload = v[3];
    s->deny_unknown = v[4];
    return 0;
}

static int read_enforce(void)
{
    char b[8] = { 0 };
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    ssize_t r;

    if (fd < 0) return -1;
    r = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (r <= 0) return -1;
    return atoi(b);
}

static int write_enforce(int v)
{
    char b[4];
    int fd, n = snprintf(b, sizeof(b), "%d", v);

    fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (fd < 0) return -errno;
    if (write(fd, b, n) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    close(fd);
    return 0;
}

static int status_mmap(struct kstatus *s)
{
    int fd = open("/sys/fs/selinux/status", O_RDONLY);
    void *p;

    if (fd < 0) return -errno;
    p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return -errno;
    memcpy(s, p, 20);
    munmap(p, 4096);
    return 0;
}

static void show_status(const char *tag)
{
    struct kstatus s;
    struct kstatus m;
    int e;

    e = read_status(&s);
    if (e) {
        printf("%s: status read error %d\n", tag, e);
        return;
    }
    printf("%s: read  version=%u sequence=%u enforcing=%u policyload=%u deny_unknown=%u | enforce=%d\n",
           tag, s.version, s.sequence, s.enforcing, s.policyload, s.deny_unknown, read_enforce());
    if (status_mmap(&m) == 0)
        printf("%s: mmap  version=%u sequence=%u enforcing=%u policyload=%u deny_unknown=%u\n",
               tag, m.version, m.sequence, m.enforcing, m.policyload, m.deny_unknown);
    else
        printf("%s: mmap  failed: %s\n", tag, strerror(errno));
}

static int sel_query(const char *node, const char *payload, char *out, size_t outsz)
{
    char path[128];
    int fd;
    ssize_t w, r;
    int e;

    snprintf(path, sizeof(path), "/sys/fs/selinux/%s", node);
    fd = open(path, O_RDWR);
    if (fd < 0) return -errno;
    w = write(fd, payload, strlen(payload));
    e = errno;
    if (w < 0) {
        close(fd);
        return -e;
    }
    r = read(fd, out, outsz - 1);
    e = errno;
    close(fd);
    if (r < 0) return -e;
    out[r] = 0;
    return (int)r;
}

static void ctx_query(const char *tag, const char *ctx)
{
    char out[256] = { 0 };
    int rc = sel_query("context", ctx, out, sizeof(out));

    if (rc < 0)
        printf("%s: context(%s) -> rc=%d (%s)\n", tag, ctx, rc, strerror(-rc));
    else
        printf("%s: context(%s) -> \"%s\"\n", tag, ctx, out);
}

static void access_query(const char *tag, const char *scon, const char *tcon, int cls)
{
    char payload[600];
    char out[256] = { 0 };
    unsigned int allowed = 0, auditallow = 0, auditdeny = 0, seqno = 0, flags = 0, pad = 0;
    int rc;

    snprintf(payload, sizeof(payload), "%s %s %d", scon, tcon, cls);
    printf("%s: -> access query \"%s\"\n", tag, payload);
    rc = sel_query("access", payload, out, sizeof(out));
    printf("%s: <- access rc=%d reply=\"%s\"\n", tag, rc, out);
    if (rc < 0) {
        printf("%s: access(%s -> %s, %d) -> rc=%d (%s)\n", tag, scon, tcon, cls, rc, strerror(-rc));
        return;
    }
    if (sscanf(out, "%x %x %x %x %u %x", &allowed, &pad, &auditallow, &auditdeny, &seqno, &flags) != 6) {
        printf("%s: access -> unparsable \"%s\"\n", tag, out);
        return;
    }
    printf("%s: access(%s -> %s, %d) -> allowed=0x%x auditdeny=0x%x seqno=%u flags=0x%x\n",
           tag, scon, tcon, cls, allowed, auditdeny, seqno, flags);
}

static int attr_write(const char *ctx)
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

static int load_policy(const char *path)
{
    static unsigned char blob[8 << 20];
    int fd = open(path, O_RDONLY);
    ssize_t n, w;
    int e;

    if (fd < 0) return -errno;
    n = read(fd, blob, sizeof(blob));
    close(fd);
    if (n <= 0) return -EIO;
    fd = open("/sys/fs/selinux/load", O_WRONLY);
    if (fd < 0) return -errno;
    w = write(fd, blob, n);
    e = errno;
    close(fd);
    printf("load %s: %zd bytes -> %zd (%s)\n", path, n, w, w < 0 ? strerror(e) : "ok");
    return w < 0 ? -e : 0;
}

static void app_checks(const char *tag, int hide_expected)
{
    struct kstatus s;
    int rc;

    printf("\n===== app view (uid %u, %s) =====\n", APP_UID, tag);
    show_status(tag);

    ctx_query(tag, "u:r:untrusted_app:s0");
    ctx_query(tag, "u:r:magisk:s0");
    ctx_query(tag, "u:r:nosuchdom_zz9:s0");

    access_query(tag, "u:r:untrusted_app:s0", "u:object_r:system_file:s0", 6);
    access_query(tag, "u:r:magisk:s0", "u:object_r:system_file:s0", 6);

    rc = attr_write("u:r:untrusted_app:s0");
    printf("%s: attr/current <- untrusted_app -> rc=%d (%s)\n", tag, rc, rc ? strerror(-rc) : "ok");
    rc = attr_write("u:r:magisk:s0");
    printf("%s: attr/current <- magisk        -> rc=%d (%s)\n", tag, rc, rc ? strerror(-rc) : "ok");

    if (read_status(&s) == 0) {
        char out[256] = { 0 };
        unsigned int a, pad, c, pad2, seqno, f;
        int r = sel_query("access", "u:r:untrusted_app:s0 u:object_r:system_file:s0 6", out, sizeof(out));
        if (r >= 0 && sscanf(out, "%x %x %x %x %u %x", &a, &pad, &c, &pad2, &seqno, &f) == 6) {
            printf("%s: INVARIANT status.policyload=%u access.seqno=%u -> %s\n",
                   tag, s.policyload, seqno,
                   (s.policyload == seqno) ? "consistent (stock)" : "INCONSISTENT (fingerprint)");
        } else {
            printf("%s: INVARIANT check failed (access rc=%d reply=\"%s\")\n", tag, r, out);
        }
    }
    (void)hide_expected;
}

static void run_app(const char *tag, int hide_expected)
{
    pid_t p;
    int st = 0;

    printf("%s: run_app: forking...\n", tag);
    p = fork();
    printf("%s: run_app: fork -> %d (errno %d)\n", tag, (int)p, errno);
    if (p == 0) {
        printf("%s: app child: setgroups...\n", tag);
        setgroups(0, NULL);
        if (setgid(APP_UID) != 0 || setuid(APP_UID) != 0) {
            printf("app: setuid failed: %s\n", strerror(errno));
            _exit(2);
        }
        printf("%s: app child: uid=%u\n", tag, (unsigned)getuid());
        app_checks(tag, hide_expected);
        printf("%s: app child: done\n", tag);
        _exit(0);
    }
    if (p > 0) {
        waitpid(p, &st, 0);
        printf("%s: run_app: child status 0x%x (sig=%d)\n", tag, st,
               WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    } else {
        printf("fork failed: %s\n", strerror(errno));
    }
}

static void dump_log(void)
{
    static char buf[1 << 20];
    int n = klogctl(3, buf, sizeof(buf) - 1);
    char *save = NULL;

    if (n <= 0) {
        printf("klogctl failed: %d\n", n);
        return;
    }
    buf[n] = 0;
    printf("\n---- kernel messages (selinux/kp) ----\n");
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strstr(line, "selinux_hide") || strstr(line, "selinux_sepolicy") ||
            strstr(line, "selinux_hide:") || strstr(line, "selinux_sepolicy:") ||
            strstr(line, "KernelPatch") || strstr(line, "stage ") ||
            strstr(line, "live sidtab") || strstr(line, "snapshot"))
            printf("%s\n", line);
    }
    printf("---- end ----\n");
}

struct app_view_state {
    volatile int ready;
    volatile int go;
    volatile int done;
    int ok;
    int enforce;
    struct kstatus st;
};

static struct app_view_state *g_app_view;

/* Fresh uid-10000 child: open/read the status and enforce nodes, stash the
 * result in shared memory.  Used while the system is enforcing, where console
 * writes (and possibly the opens) can be denied. */
static void capture_app_state(void)
{
    pid_t p;
    struct kstatus s;

    memset(g_app_view, 0, sizeof(*g_app_view));
    g_app_view->enforce = -1;
    p = fork();
    if (p == 0) {
        setgroups(0, NULL);
        setgid(APP_UID);
        setuid(APP_UID);
        if (read_status(&s) == 0) {
            g_app_view->st = s;
            g_app_view->ok = 1;
        }
        g_app_view->enforce = read_enforce();
        _exit(0);
    }
    if (p > 0) waitpid(p, NULL, 0);
}

static void run_prog(const char *path, char *const argv[])
{
    pid_t p = fork();
    if (p == 0) {
        execve(path, argv, NULL);
        printf("exec %s failed: %s\n", path, strerror(errno));
        _exit(0);
    }
    if (p > 0) waitpid(p, NULL, 0);
}

static void run_tests(void)
{
    int rc;

    g_app_view = mmap(NULL, sizeof(*g_app_view), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    printf("\n== stock, before any policy load ==\n");
    printf("sc_hello -> 0x%lx\n", (unsigned long)sc_call(SC_SUB_HELLO, NULL, 0));
    show_status("stock-nopolicy");

    printf("\n== 1. load clean (marker-free) policy, capture hook ==\n");
    rc = load_policy(POLICY_CLEAN);
    show_status("stock-clean-loaded");

    printf("\n== 2. report post-fs-data before -> snapshot ==\n");
    trigger_event("post-fs-data", "before");

    printf("\n== 3. load manager-patched policy (magisk present) ==\n");
    rc = load_policy(POLICY_ROOTED);
    show_status("stock-rooted-loaded");

    printf("\n== stock view of the patched policy (hide not enabled yet) ==\n");
    ctx_query("stock", "u:r:magisk:s0");
    access_query("stock", "u:r:untrusted_app:s0", "u:object_r:system_file:s0", 6);
    run_app("hide-off", 0);

    printf("\n== 4. report post-fs-data after -> enable ==\n");
    trigger_event("post-fs-data", "after");
    printf("selinux_hide query -> %ld\n", sc_call(SC_SUB_FEATURE, "selinux_hide", -1));
    show_status("root-after-enable");

    run_app("hide-on", 1);

    printf("\n== 4b. timing probes (QEMU/TCG, indicative only) ==\n");
    {
        char *a1[] = { (char *)"sectime2", (char *)"-c", (char *)"1", (char *)"-n",
                       (char *)"150", (char *)"-r", (char *)"3", NULL };
        char *a2[] = { (char *)"attrprobe", (char *)"-c", (char *)"1", (char *)"-n",
                       (char *)"150", (char *)"-r", (char *)"3", NULL };
        run_prog("/sectime2", a1);
        run_prog("/attrprobe", a2);
    }

    printf("\n== 5. frozen status.enforcing (observer maps the fake page first) ==\n");
    {
        pid_t obs;
        struct kstatus real;
        int rc1, rc0, okreal;

        capture_app_state();
        klog_msg("STEP5 baseline app(permissive): ok=%d fake_enforcing=%u fake_seq=%u fake_pload=%u enforce=%d",
                 g_app_view->ok,
                 g_app_view->ok ? g_app_view->st.enforcing : 999u,
                 g_app_view->ok ? g_app_view->st.sequence : 999u,
                 g_app_view->ok ? g_app_view->st.policyload : 999u,
                 g_app_view->enforce);

        memset(g_app_view, 0, sizeof(*g_app_view));
        obs = fork();
        if (obs == 0) {
            void *p = MAP_FAILED;
            int fd;

            setgroups(0, NULL);
            setgid(APP_UID);
            setuid(APP_UID);
            fd = open("/sys/fs/selinux/status", O_RDONLY);
            if (fd >= 0)
                p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
            g_app_view->ready = 1;
            while (!g_app_view->go)
                ;
            if (p != MAP_FAILED) {
                memcpy(&g_app_view->st, p, 20);
                g_app_view->ok = 1;
            }
            g_app_view->done = 1;
            _exit(0);
        }
        while (!g_app_view->ready)
            ;
        rc1 = write_enforce(1);
        g_app_view->go = 1;
        while (!g_app_view->done)
            ;
        waitpid(obs, NULL, 0);
        okreal = (read_status(&real) == 0);
        klog_msg("STEP5 during-enforce: mapped(fake) ok=%d enforcing=%u seq=%u pload=%u | real ok=%d enforcing=%u seq=%u pload=%u | setenforce1 rc=%d",
                 g_app_view->ok,
                 g_app_view->ok ? g_app_view->st.enforcing : 999u,
                 g_app_view->ok ? g_app_view->st.sequence : 999u,
                 g_app_view->ok ? g_app_view->st.policyload : 999u,
                 okreal, okreal ? real.enforcing : 999u, okreal ? real.sequence : 999u,
                 okreal ? real.policyload : 999u, rc1);
        rc0 = write_enforce(0);
        klog_msg("STEP5 setenforce0 rc=%d (console output stops here if it failed)", rc0);
    }

    printf("\n== 6. disable the feature, app should see the live policy again ==\n");
    printf("selinux_hide disable -> %ld\n", sc_call(SC_SUB_FEATURE, "selinux_hide", 0));
    printf("selinux_hide query   -> %ld\n", sc_call(SC_SUB_FEATURE, "selinux_hide", -1));
    run_app("disabled", 0);

    printf("\n=== selinux_hide sidechannel test body done ===\n");
}

int main(void)
{
    pid_t p;
    int st = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== selinux_hide sidechannel test start ===\n");
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/dev", 0755);
    mkdir("/tmp", 0777);
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mkdir("/sys/fs/selinux", 0755);
    printf("mount selinuxfs: %s\n",
           mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL) == 0 ? "ok" : strerror(errno));

    /* the feature only arms itself when this control file exists at "before" */
    mkdir("/data", 0755);
    mkdir("/data/adb", 0755);
    mkdir("/data/adb/ap", 0755);
    close(open("/data/adb/ap/selinux_hide", O_CREAT | O_WRONLY, 0644));

    /* run the body in a child: a test segfault must not panic PID 1 */
    p = fork();
    if (p == 0) {
        run_tests();
        _exit(0);
    }
    if (p > 0)
        waitpid(p, &st, 0);
    printf("\nTEST CHILD: exited=%d signaled=%d sig=%d status=0x%x\n",
           WIFEXITED(st), WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0, st);

    dump_log();
    printf("\n=== selinux_hide sidechannel test done ===\n");
    sync();
    sleep(1);
    reboot(RB_POWER_OFF);
    while (1) pause();
    return 0;
}
