/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* forward.c - the ~75 libc5 symbols that are ABI-identical to glibc.
 * Each is a thin wrapper resolving the real glibc symbol via RTLD_NEXT.
 * We deliberately do NOT include the standard headers that declare these
 * (that would clash with our redefinitions); generic 32-bit types suffice
 * since everything here is int/long/pointer-sized on i386.
 *
 * CAVEAT (flagged for later): modern 32-bit glibc may use 64-bit time_t.
 * time()/localtime() are forwarded as-is; revisit if WP misbehaves on dates.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdarg.h>
#include <dlfcn.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void  __libc_free(void *);
extern int   vsprintf(char *, const char *, va_list);
extern int   vsnprintf(char *, size_t, const char *, va_list);
extern int   vsscanf(const char *, const char *, va_list);

/* errno bridge: WP reads its own (copy-relocated, non-TLS) `errno`/`_errno`
 * global, but glibc syscall wrappers set glibc's TLS errno. Without copying
 * glibc's errno into WP's global after each call, WP sees errno==0 and
 * mishandles EAGAIN/EINTR (e.g. treats a non-blocking X read as fatal). */
extern int *__errno_location(void);
extern int _errno;                 /* -> WP's canonical errno via copy reloc */
#define SYNC_ERRNO() (_errno = *__errno_location())
/* PUSH WP's errno INTO glibc's TLS errno *before* each forwarded call. WP uses
 * the classic `errno = 0; op(); if (errno) ...` idiom, but it writes only its
 * copy-relocated _errno; glibc never sees the clear, and glibc leaves errno
 * unchanged on success — so a later SUCCESSFUL call's SYNC copies a *stale*
 * glibc errno back over WP's 0, making WP treat "no more dir entries" (and
 * similar) as a fatal error (the printer "File IO Error" was exactly this).
 * Bidirectional sync keeps the two errnos truly one value. */
#define PRE_ERRNO() (*__errno_location() = _errno)

/* forward returning a value */
#define FWD(ret, name, decl, call)                                   \
    ret name decl {                                                  \
        static ret (*fn) decl;                                       \
        if (!fn) fn = (ret (*) decl) dlsym(RTLD_NEXT, #name);        \
        PRE_ERRNO();                                                 \
        ret _r = fn call;                                            \
        SYNC_ERRNO();                                                \
        return _r;                                                   \
    }
/* forward returning void */
#define FWDV(name, decl, call)                                       \
    void name decl {                                                 \
        static void (*fn) decl;                                      \
        if (!fn) fn = (void (*) decl) dlsym(RTLD_NEXT, #name);       \
        PRE_ERRNO();                                                 \
        fn call;                                                     \
        SYNC_ERRNO();                                                \
    }

typedef int (*cmp_t)(const void *, const void *);
typedef void (*sighandler_t)(int);

/* ---- debug logging (DISPLAY/mwp handoff) --------------------------------- */
extern int  snprintf(char *, size_t, const char *, ...);
extern int  getpid(void);
extern long write(int, const void *, size_t);
extern int  open(const char *, int, ...);
static int g_debug = -1;   /* WPSHIM_DEBUG=1 enables the /tmp/wpshim.log tracing */
static void logkv(const char *k, const char *v) {
    static int fd = -2;
    if (g_debug == -1) { char *(*ge)(const char*) = (char *(*)(const char*))dlsym(RTLD_NEXT,"getenv");
                         char *e = ge ? ge("WPSHIM_DEBUG") : 0; g_debug = (e && *e=='1') ? 1 : 0; }
    if (!g_debug) return;
    if (fd == -2) fd = open("/tmp/wpshim.log", 01 | 0100 | 02000, 0644); /* WRONLY|CREAT|APPEND */
    if (fd < 0) return;
    char b[512];
    int n = snprintf(b, sizeof(b), "[%d] %s = [%s]\n", getpid(), k, v ? v : "(null)");
    if (n > 0) write(fd, b, n);
}
static int startswith(const char *s, const char *p) {
    if (!s) return 0;
    while (*p) { if (*s++ != *p++) return 0; }
    return 1;
}
static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/* ---- CUPS PostScript capture (RETRO5_CUPS) --------------------------------
 * When RETRO5_CUPS is on, WP's spooler child (wppx — which loads this shim as
 * its libc) writes a genuine %!PS-Adobe body to /tmp/_pp_<pid>_<n> and then
 * system()s `lpr -P<dev> <file>`. We tee that temp file's bytes into an
 * in-memory buffer as they are written (keyed by path), and in system()/execvp()
 * hand the buffer to CUPS via r5_cups_spool(), suppressing the real lpr.
 *
 * The FILE* spool path funnels through THIS file's own open()/write()
 * (fopen->open, fwrite->write_all->write), so one fd-level tee captures both the
 * raw-fd and the stdio path. Everything is gated on r5_cups_enabled(): with CUPS
 * off, open/write/close never touch a slot and behaviour is byte-identical. */
extern void *__libc_realloc(void *, size_t);
extern long  read(int, void *, size_t);
extern int   close(int);
extern char *getenv(const char *);
extern int   r5_cups_enabled(void);              /* patch5.c: RETRO5_CUPS on? */
extern int   r5_cups_spool(const char *dest, const void *ps, unsigned len);  /* patch5.c */

static int r5_cups_trace(void) {                 /* RETRO5_TRACE=1 -> dump captured PS + log */
    static int t = -1;
    if (t == -1) { char *e = getenv("RETRO5_TRACE"); t = (e && *e) ? 1 : 0; }
    return t;
}

#define R5CAP_MAX  4
#define R5CAP_PATH 256
static struct r5cap {
    int      used;                 /* slot claimed */
    int      fd;                   /* live fd writing this file, or -1 (closed but retained) */
    char     path[R5CAP_PATH];
    char    *buf;
    unsigned len, cap;
} r5cap[R5CAP_MAX];

/* basename of a spooler PostScript temp? WP names them _pp_<pid>_<n>. */
static int r5cap_is_ps_temp(const char *path) {
    const char *tail = path, *p;
    if (!path) return 0;
    for (p = path; *p; p++) if (*p == '/') tail = p + 1;
    return startswith(tail, "_pp_");
}
static struct r5cap *r5cap_by_path(const char *path) {
    int i;
    for (i = 0; i < R5CAP_MAX; i++)
        if (r5cap[i].used && streq(r5cap[i].path, path)) return &r5cap[i];
    return 0;
}
static struct r5cap *r5cap_by_fd(int fd) {
    int i;
    if (fd < 0) return 0;
    for (i = 0; i < R5CAP_MAX; i++)
        if (r5cap[i].used && r5cap[i].fd == fd) return &r5cap[i];
    return 0;
}
/* open() calls this after a successful open of a PS temp: (re)claim a slot. */
static void r5cap_open(const char *path, int fd) {
    struct r5cap *s = r5cap_by_path(path);
    size_t i;
    if (!s) {
        int k;
        for (k = 0; k < R5CAP_MAX && !s; k++) if (!r5cap[k].used) s = &r5cap[k];
        if (!s) s = &r5cap[0];       /* all busy: reuse slot 0 (only a handful of jobs ever) */
        if (s->buf) { __libc_free(s->buf); s->buf = 0; }
        s->cap = 0;
    }
    s->used = 1; s->fd = fd; s->len = 0;
    for (i = 0; path[i] && i < R5CAP_PATH - 1; i++) s->path[i] = path[i];
    s->path[i] = 0;
}
/* write() calls this for a tagged fd: append n bytes (n = bytes actually written). */
static void r5cap_append(struct r5cap *s, const void *buf, long n) {
    if (n <= 0) return;
    if (s->len + (unsigned)n > s->cap) {
        unsigned nc = s->cap ? s->cap * 2 : 8192;
        char *nb;
        while (nc < s->len + (unsigned)n) nc *= 2;
        nb = (char *)__libc_realloc(s->buf, nc);
        if (!nb) return;             /* OOM: keep what we have (system() falls back to disk) */
        s->buf = nb; s->cap = nc;
    }
    __builtin_memcpy(s->buf + s->len, buf, (size_t)n);
    s->len += (unsigned)n;
}
/* Fallback: read a fully-written spool file from disk. Caller frees the result. */
static char *r5cap_read_file(const char *path, unsigned *outlen) {
    int fd = open(path, 0 /*O_RDONLY*/, 0);
    char *buf = 0; unsigned len = 0, cap = 0;
    *outlen = 0;
    if (fd < 0) return 0;
    for (;;) {
        long n;
        if (len + 8192 > cap) {
            unsigned nc = cap ? cap * 2 : 65536; char *nb;
            while (nc < len + 8192) nc *= 2;
            nb = (char *)__libc_realloc(buf, nc);
            if (!nb) break;
            buf = nb; cap = nc;
        }
        n = read(fd, buf + len, 8192);
        if (n <= 0) break;
        len += (unsigned)n;
    }
    close(fd);
    *outlen = len;
    return buf;
}
/* If argv is the wppx spool (`lpr/lp/qprt -P<dev> /tmp/_pp_*`), route its captured
 * PostScript to CUPS. Returns 1 if handled (caller suppresses the real command). */
static int r5_spool_argv(char *const *argv) {
    const char *bn, *p, *dest = 0, *file = 0;
    struct r5cap *s;
    const char *ps; unsigned len = 0; char *disk = 0; int handled, is_ps, i;
    if (!argv || !argv[0]) return 0;
    bn = argv[0];
    for (p = argv[0]; *p; p++) if (*p == '/') bn = p + 1;
    if (!streq(bn, "lpr") && !streq(bn, "lp") && !streq(bn, "qprt")) return 0;
    for (i = 1; argv[i]; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && (a[1] == 'P' || a[1] == 'd')) {       /* -P<dev> (lpr/qprt) / -d<dev> (lp) */
            if (a[2]) dest = a + 2;
            else if (argv[i + 1]) dest = argv[++i];              /* split "-P dev" form */
        } else if (a[0] != '-' && r5cap_is_ps_temp(a)) {
            file = a;
        }
    }
    if (!file) return 0;                                         /* not our spool -> real command runs */

    s = r5cap_by_path(file);
    if (s && s->len > 0) { ps = s->buf; len = s->len; }
    else { disk = r5cap_read_file(file, &len); ps = disk; }      /* buffer empty -> read from disk */
    if (!ps || !len) { if (disk) __libc_free(disk); return 0; }  /* nothing to send -> real lpr */

    is_ps = (len >= 4 && ps[0] == '%' && ps[1] == '!' && ps[2] == 'P' && ps[3] == 'S');
    if (r5_cups_trace()) {
        char dp[64], b[256]; int k;
        int dfd = open((k = snprintf(dp, sizeof dp, "/tmp/r5_captured_%d.ps", getpid()), dp),
                       01 | 0100 | 01000 /*O_WRONLY|O_CREAT|O_TRUNC*/, 0644);
        if (dfd >= 0) { long off = 0; while (off < (long)len) {
            long w = write(dfd, ps + off, len - off); if (w <= 0) break; off += w; } close(dfd); }
        k = snprintf(b, sizeof b,
            "retro5: captured %u bytes, %%!PS=%s, dest=%s -> %s, lpr suppressed\n",
            len, is_ps ? "yes" : "no", (dest && *dest) ? dest : "(default)", dp);
        if (k > 0) write(2, b, (size_t)k);
    }

    handled = r5_cups_spool(dest, ps, len);
    if (disk) __libc_free(disk);
    return handled;
}
/* system() passes a shell string; tokenise on whitespace (WP builds a plain
 * `lpr  -P<dev> <file>` command with no quoting) and reuse r5_spool_argv. */
static int r5_spool_cmd(const char *cmd) {
    char buf[1024]; char *tok[64]; int nt = 0; size_t i = 0; char *p;
    if (!cmd) return 0;
    while (cmd[i] && i < sizeof buf - 1) { buf[i] = cmd[i]; i++; }
    if (cmd[i]) return 0;                    /* too long to parse safely -> let the shell run it */
    buf[i] = 0;
    p = buf;
    while (*p && nt < 63) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    tok[nt] = 0;
    return nt ? r5_spool_argv(tok) : 0;
}

/* xwppmgr -> modern CUPS config tool (RETRO5_CUPS). Both "Printer Control..."
 * (Program menu, queue/jobs) and "Printer Create/Edit..." (Select-Printer dialog,
 * add/config) fork+exec the legacy manager shbin10/xwppmgr. retro5 is that child's
 * libc, so we replace the exec with a modern tool. RETRO5_PRINTER_ADMIN overrides
 * the default ("gnome-control-center printers"), tokenised on spaces (e.g.
 * "xdg-open http://localhost:631/admin"). If the replacement exec fails (tool
 * absent), we return so the caller runs the real xwppmgr — graceful fallback.
 * (The queue-vs-config distinction lives in an encrypted work-file, not argv, so
 * both open one printer panel; gnome-control-center printers covers both.) */
static int r5_is_xwppmgr(const char *file) {
    const char *bn = file, *p;
    if (!file) return 0;
    for (p = file; *p; p++) if (*p == '/') bn = p + 1;
    return streq(bn, "xwppmgr");
}
static void r5_admin_redirect(const char *file) {
    static int (*ev)(const char *, char *const *);
    char buf[256], *av[16], *p; int n = 0; const char *env; size_t i;
    if (!r5_cups_enabled() || !r5_is_xwppmgr(file)) return;
    env = getenv("RETRO5_PRINTER_ADMIN");
    if (!env || !*env) env = "gnome-control-center printers";
    for (i = 0; env[i] && i < sizeof buf - 1; i++) buf[i] = env[i];
    buf[i] = 0;
    p = buf;
    while (*p && n < 15) { while (*p == ' ') p++; if (!*p) break; av[n++] = p;
                           while (*p && *p != ' ') p++; if (*p) *p++ = 0; }
    av[n] = 0;
    if (!n) return;
    if (r5_cups_trace()) { char b[192]; int k = snprintf(b, sizeof b,
        "retro5: xwppmgr -> %s (CUPS admin)\n", buf); if (k > 0) write(2, b, (size_t)k); }
    if (!ev) ev = (int (*)(const char *, char *const *)) dlsym(RTLD_NEXT, "execvp");
    if (ev) ev(av[0], av);        /* success never returns; on failure fall through to real xwppmgr */
}

/* ---- per-instance print-server path rewrite ------------------------------
 * WP's xwp<->wpexc handshake uses fixed-name files in /tmp/wpc-<user>-<host>/
 * keyed only on the MAJOR VERSION "8", not per instance: the excmsg8 FIFO, the
 * .wpexc8.man manifest, and the .wpexc8.LCK lock. Two WP 8.0 instances therefore
 * collide -- the second recreates excmsg8, orphaning the first (which then spins
 * ~5 min and shows a false "print server not running"). Fix: make those three
 * names per-instance by inserting a shared token. retro5 loads in BOTH xwp and
 * the wpexc it spawns, so rewriting the path ARGUMENT of every path-taking libc
 * call in both processes keeps them in agreement WITHOUT touching manifest
 * CONTENTS: wpexc writes the base name "excmsg8" into the manifest, and when xwp
 * later open()s that base name we rewrite it again with the same token, so both
 * converge on the identical per-instance path.
 *
 * Gated on RETRO5_WPEXC_ID (exported by the WP launcher as $$): any program that
 * loads retro5.so WITHOUT the token is never rewritten. Token read once + cached.
 *
 * CRITICAL: this must be applied at EVERY libc path entry point WP can reach --
 * not only open/mknod/unlink here in forward.c, but also stat/lstat (os5.c),
 * which is why r5_wpexc_rewrite is exported (non-static). If one entry point
 * rewrites and another does not, xwp creates ".wpexc8.<id>.LCK" via open() but
 * then stat()s the un-rewritten ".wpexc8.LCK", sees it absent, and skips
 * releasing the lock -- wpexc then blocks forever and dies with "error 21". */
extern char *getenv(const char *);
static const char *wpexc_id(void) {
    static const char *id; static int looked;
    if (!looked) { looked = 1; id = getenv("RETRO5_WPEXC_ID"); if (id && !*id) id = 0; }
    return id;
}
/* If PATH's basename is one of WP's fixed print-server file names, write a
 * per-instance variant into BUF and return BUF; otherwise return PATH unchanged
 * (also when the token is unset or the rewrite would overflow BUF). Gated only on
 * (token set) + (EXACT basename match) -- no directory-prefix requirement, so a
 * relative open (e.g. WP chdir'd into the wpc dir) is rewritten identically.
 * Exact basename match keeps it idempotent (".wpexc8.1234.LCK" never re-matches). */
const char *r5_wpexc_rewrite(const char *path, char *buf, size_t bufsz) {
    const char *id = wpexc_id();
    if (!id || !path) return path;
    const char *tail = path;
    for (const char *p = path; *p; p++) if (*p == '/') tail = p + 1;
    size_t dlen = (size_t)(tail - path);
    char nb[128]; int m;
    if      (streq(tail, "excmsg8"))      m = snprintf(nb, sizeof nb, "excmsg8.%s", id);
    else if (streq(tail, ".wpexc8.man"))  m = snprintf(nb, sizeof nb, ".wpexc8.%s.man", id);
    else if (streq(tail, ".wpexc8.LCK"))  m = snprintf(nb, sizeof nb, ".wpexc8.%s.LCK", id);
    else if (streq(tail, ".wpexc.man"))   m = snprintf(nb, sizeof nb, ".wpexc.%s.man", id);
    else if (streq(tail, ".wpexc.LCK"))   m = snprintf(nb, sizeof nb, ".wpexc.%s.LCK", id);
    else return path;
    if (m < 0 || (size_t)m >= sizeof nb) return path;   /* basename too long */
    if (dlen + (size_t)m + 1 > bufsz) return path;      /* overflow -> unchanged */
    for (size_t i = 0; i < dlen; i++) buf[i] = path[i];
    for (int i = 0; i <= m; i++) buf[dlen + i] = nb[i]; /* copies trailing NUL */
    return buf;
}
/* log a key with an integer value (result/errno tracing for spawn calls) */
static void logint(const char *k, long v) {
    char b[32]; int i = 0, neg = 0; unsigned long u;
    if (v < 0) { neg = 1; u = (unsigned long)(-v); } else u = (unsigned long)v;
    char t[24]; int j = 0;
    do { t[j++] = '0' + (u % 10); u /= 10; } while (u);
    if (neg) b[i++] = '-';
    while (j) b[i++] = t[--j];
    b[i] = 0;
    logkv(k, b);
}
/* forward + log result and errno (for tracing IPC setup) */
#define FWDLOG(ret, name, decl, call)                                \
    ret name decl {                                                  \
        static ret (*fn) decl;                                       \
        if (!fn) fn = (ret (*) decl) dlsym(RTLD_NEXT, #name);        \
        PRE_ERRNO();                                                 \
        ret _r = fn call;                                            \
        SYNC_ERRNO();                                                \
        logint(#name " ret", (long)_r);                             \
        if ((long)_r < 0) logint("  " #name " errno", *__errno_location()); \
        return _r;                                                   \
    }
/* fires in EVERY process that loads the shim - reveals wpexc-as-child even
 * when xwp has redirected its stdio away from us. */
extern long read(int, void *, size_t);
extern int close(int);
extern int backtrace(void **, int);
extern void backtrace_symbols_fd(void *const *, int, int);
static int g_logfd(void) {   /* reopen the log fd for use inside a signal handler */
    return open("/tmp/wpshim.log", 01 | 0100 | 02000, 0644);
}
extern sighandler_t signal(int, sighandler_t);
extern int raise(int);
static void crash_handler(int signo) {
    int fd = g_logfd();
    if (fd >= 0) {
        char b[64];
        int n = snprintf(b, sizeof(b), "[%d] *** CRASH signal %d ***\n", getpid(), signo);
        if (n > 0) write(fd, b, n);
        void *bt[48];
        int k = backtrace(bt, 48);
        backtrace_symbols_fd(bt, k, fd);
        close(fd);
    }
    signal(signo, (sighandler_t)0 /*SIG_DFL*/);
    raise(signo);
}
__attribute__((constructor))
static void shim_hello(void) {
    /* only GENUINE fatal crash signals - NOT SIGPIPE/TERM/HUP (those are normal
     * operational signals; catching+re-raising them fatally was killing xwp and
     * the wpexc print-server intermittently on FIFO writes). */
    signal(11 /*SEGV*/, crash_handler);
    signal(6  /*ABRT*/, crash_handler);
    signal(4  /*ILL */, crash_handler);
    signal(7  /*BUS */, crash_handler);
    signal(8  /*FPE */, crash_handler);
    signal(13 /*PIPE*/, (sighandler_t)1 /*SIG_IGN*/);  /* WP relies on EPIPE, not the signal */
    char cmd[256]; int i;
    int fd = open("/proc/self/cmdline", 0 /*O_RDONLY*/, 0);
    long n = fd >= 0 ? read(fd, cmd, sizeof(cmd) - 1) : 0;
    if (fd >= 0) close(fd);
    if (n < 0) n = 0;
    cmd[n] = 0;
    for (i = 0; i < n - 1; i++) if (cmd[i] == 0) cmd[i] = ' ';   /* argv sep -> space */
    logkv(">>> shim loaded, cmdline", cmd);
}
__attribute__((destructor))
static void shim_bye(void) { logkv("<<< shim process exiting", ""); }

/* ---- memory (route to glibc internals; breaks dlsym/malloc recursion) ----- */
void *malloc(size_t n)            { return __libc_malloc(n); }
void *calloc(size_t a, size_t b)  { return __libc_calloc(a, b); }
void *realloc(void *p, size_t n)  { return __libc_realloc(p, n); }
void  free(void *p)               { __libc_free(p); }

/* ---- string / mem --------------------------------------------------------- */
FWD(void *, memcpy,  (void *a, const void *b, size_t c), (a, b, c))
FWD(void *, memmove, (void *a, const void *b, size_t c), (a, b, c))
FWD(void *, memset,  (void *a, int b, size_t c),         (a, b, c))
FWDV(bcopy,          (const void *a, void *b, size_t c), (a, b, c))
FWDV(bzero,          (void *a, size_t b),                (a, b))
FWD(size_t, strlen,  (const char *a),                    (a))
FWD(char *, strcpy,  (char *a, const char *b),           (a, b))
FWD(char *, strncpy, (char *a, const char *b, size_t c), (a, b, c))
FWD(char *, strcat,  (char *a, const char *b),           (a, b))
FWD(int,    strcmp,  (const char *a, const char *b),     (a, b))
FWD(int,    strncmp, (const char *a, const char *b, size_t c), (a, b, c))
FWD(int,    strcasecmp,(const char *a, const char *b),   (a, b))
FWD(char *, strchr,  (const char *a, int b),             (a, b))
FWD(char *, strrchr, (const char *a, int b),             (a, b))
/* Additional libc5 symbols used by the WordPerfect 8.1 suite filters
 * (inww8/outwp6/cvt/cjpeg/djpeg/FLEXlm) but not by the 8.0 disc — found by
 * scanning all 52 suite binaries against the bundled libc.so.5.4.46. */
FWD(void *, memchr,   (const void *a, int b, size_t c),  (a, b, c))
FWD(char *, strerror, (int a),                           (a))
FWD(char *, realpath, (const char *a, char *b),          (a, b))
FWD(void *, gmtime,   (const void *a),                   (a))
/* __write: libc5 alias of write; forward straight to glibc's write. */
long __write(int a, const void *b, size_t c) {
    static long (*fn)(int, const void *, size_t);
    if (!fn) fn = (long (*)(int, const void *, size_t)) dlsym(RTLD_NEXT, "write");
    PRE_ERRNO();
    long _r = fn(a, b, c);
    SYNC_ERRNO();
    return _r;
}
FWD(char *, strstr,  (const char *a, const char *b),     (a, b))
FWD(char *, strpbrk, (const char *a, const char *b),     (a, b))
FWD(char *, strtok,  (char *a, const char *b),           (a, b))
int atoi(const char *a) {
    static int (*fn)(const char *);
    if (!fn) fn = (int (*)(const char *)) dlsym(RTLD_NEXT, "atoi");
    int r = fn(a);
    logkv("atoi", a);
    return r;
}
FWD(long,   __strtol_internal, (const char *a, char **b, int c, int d), (a, b, c, d))

/* ---- process / misc ------------------------------------------------------- */
/* abort() is declared noreturn; forward then mark unreachable so GCC agrees. */
void abort(void) {
    static void (*fn)(void);
    if (!fn) fn = (void (*)(void)) dlsym(RTLD_NEXT, "abort");
    PRE_ERRNO();
    fn();
    __builtin_unreachable();
}
/* exit: glibc's exit runs _IO_cleanup (flush all glibc streams), which
 * segfaults given our interposed/libc5-layout FILEs. Run the registered
 * atexit/__cxa_atexit handlers ourselves, then _exit — skipping the crash.
 *
 * But __cxa_finalize itself can still fault: libstdc++'s iostream `Init`
 * destructor (dragged in transitively by cairo's text path -> harfbuzz) flushes
 * std::cout, which is the copy-relocated *libc5* _IO_stdout_, using the DEEPBIND
 * libstdc++'s *glibc* fflush -> it walks a glibc vtable that isn't there and
 * segfaults. That Init object is constructed at C++ startup (earliest), so its
 * destructor runs LAST in __cxa_finalize, after WP's own atexit handlers. So we
 * guard the finalize with a SIGSEGV catch: WP's cleanup runs, and if the trailing
 * libstdc++ flush faults we siglongjmp out and _exit cleanly instead of dying. */
extern void __cxa_finalize(void *);
extern void _exit(int);
/* If the trailing libstdc++ flush faults, just _exit from the handler — we are
 * already terminating, WP's own handlers ran first, and _exit is a direct
 * syscall (async-signal-safe). No setjmp: retro5 exports a libc5 siglongjmp but
 * imports glibc's __sigsetjmp, so that pair is mismatched and unreliable. */
static volatile int r5_exit_code;
static void r5_exit_segv(int sig) { (void)sig; _exit(r5_exit_code); }
void exit(int code) {
    static int busy = 0;
    if (!busy) {
        busy = 1;
        r5_exit_code = code;
        sighandler_t prev = signal(11 /*SEGV*/, r5_exit_segv);
        __cxa_finalize(0);               /* faults in the tail -> handler _exit()s */
        signal(11 /*SEGV*/, prev);       /* no fault: restore the crash logger */
    }
    _exit(code);
}
/* atexit is NOT dynamically exported by modern glibc (it's in
 * libc_nonshared.a), so RTLD_NEXT finds nothing. Implement via __cxa_atexit,
 * which glibc does export. */
extern int __cxa_atexit(void (*)(void *), void *, void *);
static void atexit_thunk(void *fn) { ((void (*)(void))fn)(); }
int atexit(void (*fn)(void)) { return __cxa_atexit(atexit_thunk, (void *)fn, 0); }
int system(const char *a) {
    static int (*fn)(const char *);
    if (!fn) fn = (int (*)(const char *)) dlsym(RTLD_NEXT, "system");
    logkv("system", a);
    if (a && r5_cups_enabled() && r5_spool_cmd(a)) {   /* wppx spool -> CUPS: suppress the real lpr */
        logkv("  system CUPS-routed (lpr suppressed)", a);
        SYNC_ERRNO();
        return 0;                                      /* success, exactly as a good lpr would report */
    }
    int r = fn(a);
    SYNC_ERRNO(); logint("  system ret", r);
    return r;
}
char *getenv(const char *name) {
    static char *(*fn)(const char *);
    if (!fn) fn = (char *(*)(const char *)) dlsym(RTLD_NEXT, "getenv");
    char *r = fn(name);
    logkv(name, r);
    return r;
}
int putenv(char *s) {
    static int (*fn)(char *);
    if (!fn) fn = (int (*)(char *)) dlsym(RTLD_NEXT, "putenv");
    logkv("putenv", s);
    return fn(s);
}
FWD(int,   getpid, (void), ())
FWD(int,   getuid, (void), ())
FWD(int,   getegid,(void), ())

/* geteuid override for `-admin` font install on a USER-OWNED (writable) install.
 * WordPerfect's admin/font-install mode (`xwp -admin`, and its `xwpfi` helper) is gated by
 * geteuid()==0 (auth fn 0x857ee20: geteuid -> test -> jne authorized), then refuses non-root with
 * "Not authorized to run as administrator" and exit(2). But this WP lives in a user-owned tree, so
 * that root requirement is just permission theatre — the install writes wp.drs under the user's own
 * shlib10. Report euid 0 ONLY when BOTH hold:
 *   (a) admin context — argv contains "-admin", or this process IS the xwpfi helper; and
 *   (b) the WP install dir ($WPC) is writable by the real user.
 * A SYSTEM install (root-owned, not writable) still sees the real euid, so WP's protection is intact;
 * and normal (non-admin) WP runs never see euid 0, keeping the many other geteuid callers untouched. */
extern int access(const char *, int);
static int r5_admin_local(void) {
    static int cached = -1;
    int fd; char b[1024]; long n; int admin = 0;
    const char *wpc;
    if (cached >= 0) return cached;
    cached = 0;
    fd = open("/proc/self/cmdline", 0 /*O_RDONLY*/, 0);
    if (fd >= 0) {
        n = read(fd, b, sizeof b - 1); close(fd);
        if (n > 0) {
            long i; b[n] = 0;
            for (i = 0; i < n; i++)
                if (i == 0 || b[i-1] == 0) {                 /* start of an argv token */
                    const char *t = b + i, *bn = t, *p;
                    for (p = t; *p; p++) if (*p == '/') bn = p + 1;   /* basename */
                    if (!__builtin_strcmp(bn, "xwpfi") || !__builtin_strcmp(t, "-admin")) admin = 1;
                }
        }
    }
    if (!admin) return cached;                               /* not admin context -> real euid */
    wpc = getenv("WPC");
    if (wpc && *wpc && access(wpc, 2 /*W_OK*/) == 0) cached = 1;   /* writable local install */
    return cached;
}
int geteuid(void) {
    static int (*fn)(void);
    if (r5_admin_local()) return 0;
    if (!fn) fn = (int (*)(void)) dlsym(RTLD_NEXT, "geteuid");
    return fn ? fn() : 0;
}
FWD(unsigned, alarm, (unsigned a), (a))
FWD(unsigned, sleep, (unsigned a), (a))
FWD(int,   kill,   (int a, int b), (a, b))
FWD(int,   uname,  (void *a), (a))
FWD(void *, bsearch,(const void *a, const void *b, size_t c, size_t d, cmp_t e), (a,b,c,d,e))
FWDV(qsort, (void *a, size_t b, size_t c, cmp_t d), (a, b, c, d))
FWD(sighandler_t, signal, (int a, sighandler_t b), (a, b))
FWD(void *, localtime, (const void *a), (a))
FWDV(tzset, (void), ())
FWD(long,   time,   (long *a), (a))

/* ---- files / fs (non-FILE) ------------------------------------------------ */
/* access/unlink/rename take the print-server path names, so they are explicit
 * (not FWD) to apply the per-instance rewrite before forwarding. */
int access(const char *a, int b) {
    static int (*fn)(const char *, int);
    if (!fn) fn = (int (*)(const char *, int)) dlsym(RTLD_NEXT, "access");
    char buf[512]; const char *p = r5_wpexc_rewrite(a, buf, sizeof buf);
    PRE_ERRNO(); int _r = fn(p, b); SYNC_ERRNO(); return _r;
}
FWD(int,   chdir,   (const char *a), (a))
FWD(int,   chmod,   (const char *a, unsigned b), (a, b))
FWD(int,   fchmod,  (int a, unsigned b), (a, b))
FWD(int,   mkdir,   (const char *a, unsigned b), (a, b))
FWD(int,   rmdir,   (const char *a), (a))
int unlink(const char *a) {
    static int (*fn)(const char *);
    if (!fn) fn = (int (*)(const char *)) dlsym(RTLD_NEXT, "unlink");
    char buf[512]; const char *p = r5_wpexc_rewrite(a, buf, sizeof buf);
    PRE_ERRNO(); int _r = fn(p); SYNC_ERRNO(); return _r;
}
int rename(const char *a, const char *b) {
    static int (*fn)(const char *, const char *);
    if (!fn) fn = (int (*)(const char *, const char *)) dlsym(RTLD_NEXT, "rename");
    char ba[512], bb[512];
    const char *pa = r5_wpexc_rewrite(a, ba, sizeof ba);
    const char *pb = r5_wpexc_rewrite(b, bb, sizeof bb);
    PRE_ERRNO(); int _r = fn(pa, pb); SYNC_ERRNO(); return _r;
}
int close(int a) {
    static int (*fn)(int);
    if (!fn) fn = (int (*)(int)) dlsym(RTLD_NEXT, "close");
    /* CUPS mode: detach a tagged spool fd but KEEP its buffer — wppx closes the
     * %!PS temp before system()s lpr, and system() still needs the captured bytes. */
    if (r5_cups_enabled()) { struct r5cap *s = r5cap_by_fd(a); if (s) s->fd = -1; }
    PRE_ERRNO(); int _r = fn(a); SYNC_ERRNO(); return _r;
}
int g_drs_fd = -1;   /* set by open() when wp.drs is opened; traced below */
/* trace the WP IPC channels (excmsg8 FIFO + per-client response files) to see
 * the xwp<->wpexc print-server message exchange. */
int g_ipc_fds[16]; int g_ipc_n = 0;
static int is_ipc(int fd){ for(int i=0;i<g_ipc_n;i++) if(g_ipc_fds[i]==fd) return 1; return 0; }
long read(int a, void *b, size_t c) {
    static long (*fn)(int, void *, size_t);
    if (!fn) fn = (long (*)(int, void *, size_t)) dlsym(RTLD_NEXT, "read");
    long r = fn(a, b, c); SYNC_ERRNO();
    if (a == g_drs_fd) {
        logint("drs read req", (long)c); logint("  drs read got", r);
        if (r < 0) logint("  drs read errno", *__errno_location());
    }
    if (is_ipc(a)) { logint("IPC read fd", a); logint("  IPC read got", r);
        if (r < 0) logint("  IPC read errno", *__errno_location()); }
    return r;
}
long write(int a, const void *b, size_t c) {
    static long (*fn)(int, const void *, size_t);
    if (!fn) fn = (long (*)(int, const void *, size_t)) dlsym(RTLD_NEXT, "write");
    long r = fn(a, b, c); SYNC_ERRNO();
    if (is_ipc(a)) { logint("IPC write fd", a); logint("  IPC write sent", r);
        if (r < 0) logint("  IPC write errno", *__errno_location()); }
    if (r > 0 && r5_cups_enabled()) {                  /* tee a tagged %!PS spool temp into memory */
        struct r5cap *s = r5cap_by_fd(a);
        if (s) r5cap_append(s, b, r);
    }
    return r;
}
FWD(long,  readv,   (int a, const void *b, int c), (a, b, c))
FWD(long,  writev,  (int a, const void *b, int c), (a, b, c))
long lseek(int a, long b, int c) {
    static long (*fn)(int, long, int);
    if (!fn) fn = (long (*)(int, long, int)) dlsym(RTLD_NEXT, "lseek");
    long r = fn(a, b, c); SYNC_ERRNO();
    if (a == g_drs_fd) { logint("drs lseek off", b); logint("  drs lseek whence", c); logint("  drs lseek ret", r); }
    return r;
}
FWD(int,   fsync,   (int a), (a))
FWD(int,   ftruncate,(int a, long b), (a, b))
FWD(char *,getcwd,  (char *a, size_t b), (a, b))
FWD(int,   utime,   (const char *a, const void *b), (a, b))
FWD(int,   select,  (int a, void *b, void *c, void *d, void *e), (a,b,c,d,e))

/* ---- sockets / net -------------------------------------------------------- */
FWDLOG(int, socket, (int a, int b, int c), (a, b, c))
FWDLOG(int, connect, (int a, const void *b, unsigned c), (a, b, c))
FWD(int,   shutdown,(int a, int b), (a, b))
FWD(int,   setsockopt,(int a,int b,int c,const void*d,unsigned e),(a,b,c,d,e))
FWD(int,   getpeername,(int a, void *b, unsigned *c), (a, b, c))
FWD(int,   getsockname,(int a, void *b, unsigned *c), (a, b, c))
FWD(void *,gethostbyname,(const char *a), (a))
FWD(int,   gethostname,(char *a, size_t b), (a, b))
FWD(void *,getservbyname,(const char *a, const char *b), (a, b))
FWD(unsigned, inet_addr,(const char *a), (a))
FWD(char *,inet_ntoa,(unsigned a), (a))   /* struct in_addr passed by value == 4 bytes */
FWD(int,   gettimeofday,(void *a, void *b), (a, b))

/* ---- locale / wide -------------------------------------------------------- */
FWD(char *,setlocale,(int a, const char *b), (a, b))
FWD(size_t,mbstowcs,(void *a, const char *b, size_t c), (a, b, c))
FWD(int,   mbtowc,  (void *a, const char *b, size_t c), (a, b, c))
FWD(size_t,wcstombs,(char *a, const void *b, size_t c), (a, b, c))
FWD(int,   wctomb,  (char *a, int b), (a, b))

/* ---- regex (forwarded; regex_t size differs — revisit if it misbehaves) --- */
FWD(int,  regcomp, (void *a, const char *b, int c), (a, b, c))
FWD(int,  regexec, (const void *a, const char *b, size_t c, void *d, int e), (a,b,c,d,e))
FWDV(regfree, (void *a), (a))

/* ---- extra symbols needed by xwpfi --------------------------------------- */
int execvp(const char *a, char *const *b) {
    static int (*fn)(const char *, char *const *);
    if (!fn) fn = (int (*)(const char *, char *const *)) dlsym(RTLD_NEXT, "execvp");
    logkv("execvp", a);
    if (b) for (int i = 0; b[i] && i < 12; i++) logkv("  execvp argv", b[i]);
    r5_admin_redirect(a);          /* xwppmgr -> modern CUPS tool (returns only if that exec failed) */
    /* Safety twin of the system() hook: if wppx spools via execvp(lpr...) rather than
     * system(), route it to CUPS and exit success (a successful exec never returns). */
    if (b && r5_cups_enabled() && r5_spool_argv(b)) {
        logkv("  execvp CUPS-routed (lpr suppressed)", a);
        _exit(0);
    }
    { extern char **environ; if (environ) for (int i = 0; environ[i]; i++)
        if (startswith(environ[i], "WP") || startswith(environ[i], "SHTMP")
            || startswith(environ[i], "TMPDIR")) logkv("  child env", environ[i]); }
    int r = fn(a, b);
    SYNC_ERRNO(); logint("  execvp ret", r); logint("  execvp errno", *__errno_location());
    return r;
}
void _exit(int a) {
    static void (*fn)(int);
    if (!fn) fn = (void (*)(int)) dlsym(RTLD_NEXT, "_exit");
    logint("_exit code", a);
    fn(a);
    for (;;) {}
}
int fork(void) {
    static int (*fn)(void);
    if (!fn) fn = (int (*)(void)) dlsym(RTLD_NEXT, "fork");
    int r = fn();
    SYNC_ERRNO();
    if (r != 0) { logint("fork ret", r); if (r < 0) logint("  fork errno", *__errno_location()); }
    return r;
}
FWDLOG(int, pipe, (int *a), (a))
FWD(int,   wait,   (int *a), (a))
FWD(long,  times,  (void *a), (a))
FWD(int,   symlink,(const char *a, const char *b), (a, b))
FWD(unsigned, umask,(unsigned a), (a))
FWD(void *,getgrgid,(unsigned a), (a))
FWD(int,   mblen,  (const char *a, size_t b), (a, b))
FWD(int,   rand,   (void), ())
FWD(long,  strtol, (const char *a, char **b, int c), (a, b, c))
FWD(int,   toupper,(int a), (a))
FWD(int,   remove, (const char *a), (a))
FWD(long,  atol,   (const char *a), (a))
FWD(int,   dup,    (int a), (a))
FWD(char *,re_comp,(const char *a), (a))
FWD(int,   re_exec,(const char *a), (a))

/* execl: repack varargs into an argv and hand off to glibc execv */
extern int execv(const char *, char *const *);
int execl(const char *path, const char *arg0, ...) {
    char *argv[64]; int n = 0;
    argv[n++] = (char *)arg0;
    va_list ap; va_start(ap, arg0);
    while (n < 63 && (argv[n] = va_arg(ap, char *)) != 0) n++;
    argv[n] = 0; va_end(ap);
    return execv(path, argv);
}

extern int vscanf(const char *, va_list);
int scanf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int r = vscanf(fmt, ap); va_end(ap); return r;
}

/* ==== suite-wide batch: the 101 symbols the whole WP set imports =========== */
/* sockets / net */
FWD(int, accept, (int a, void *b, unsigned *c), (a,b,c))
FWDLOG(int, bind, (int a, const void *b, unsigned c), (a,b,c))
FWD(int, listen, (int a, int b), (a,b))
FWDLOG(int, socketpair, (int a,int b,int c,int *d), (a,b,c,d))
FWD(long, recvfrom, (int a,void*b,size_t c,int d,void*e,unsigned*f), (a,b,c,d,e,f))
FWD(long, sendto, (int a,const void*b,size_t c,int d,const void*e,unsigned f), (a,b,c,d,e,f))
FWD(void *, gethostbyaddr, (const void*a,unsigned b,int c), (a,b,c))
FWD(int, getdomainname, (char*a,size_t b), (a,b))
FWD(long, gethostid, (void), ())
FWD(unsigned short, htons, (unsigned short a), (a))
FWD(unsigned, ntohl, (unsigned a), (a))
FWD(unsigned short, ntohs, (unsigned short a), (a))
/* string / mem */
FWD(void *, memccpy, (void*a,const void*b,int c,size_t d), (a,b,c,d))
FWD(int, memcmp, (const void*a,const void*b,size_t c), (a,b,c))
FWD(size_t, strcspn, (const char*a,const char*b), (a,b))
FWD(char *, strdup, (const char*a), (a))
FWD(int, strncasecmp, (const char*a,const char*b,size_t c), (a,b,c))
FWD(char *, strncat, (char*a,const char*b,size_t c), (a,b,c))
/* ctype (functions in libc5) */
FWD(int, isalnum,(int a),(a)) FWD(int, isalpha,(int a),(a)) FWD(int, isascii,(int a),(a))
FWD(int, isdigit,(int a),(a)) FWD(int, islower,(int a),(a)) FWD(int, isspace,(int a),(a))
FWD(int, isxdigit,(int a),(a)) FWD(int, isatty,(int a),(a)) FWD(int, tolower,(int a),(a))
/* number conversion */
FWD(double, atof, (const char*a), (a))
FWD(double, strtod, (const char*a,char**b), (a,b))
FWD(double, __strtod_internal, (const char*a,char**b,int c), (a,b,c))
FWD(char *, ecvt, (double a,int b,int*c,int*d), (a,b,c,d))
FWD(char *, fcvt, (double a,int b,int*c,int*d), (a,b,c,d))
FWD(char *, gcvt, (double a,int b,char*c), (a,b,c))
FWD(double, modf, (double a,double*b), (a,b))
/* process / sys */
int execv(const char *path, char *const *argv) {
    static int (*fn)(const char *, char *const *);
    if (!fn) fn = (int (*)(const char *, char *const *)) dlsym(RTLD_NEXT, "execv");
    logkv("execv", path);
    if (argv) for (int i = 0; argv[i] && i < 8; i++) logkv("  execv argv", argv[i]);
    r5_admin_redirect(path);       /* xwppmgr -> modern CUPS tool (returns only if that exec failed) */
    int r = fn(path, argv);
    SYNC_ERRNO(); logint("  execv FAILED errno", *__errno_location());
    return r;
}
int execve(const char *path, char *const *argv, char *const *envp) {
    static int (*fn)(const char *, char *const *, char *const *);
    if (!fn) fn = (int (*)(const char *, char *const *, char *const *)) dlsym(RTLD_NEXT, "execve");
    logkv("execve", path);
    if (argv) for (int i = 0; argv[i] && i < 8; i++) logkv("  execve argv", argv[i]);
    if (envp) for (int i = 0; envp[i]; i++)
        if (startswith(envp[i], "DISPLAY")) logkv("  execve DISPLAY", envp[i]);
    r5_admin_redirect(path);       /* xwppmgr -> modern CUPS tool (returns only if that exec failed) */
    int r = fn(path, argv, envp);
    SYNC_ERRNO(); logint("  execve FAILED errno", *__errno_location());
    return r;
}
FWD(int, getpgrp,(void),()) FWD(int, setpgrp,(void),()) FWD(int, setsid,(void),())
FWD(int, setuid,(unsigned a),(a)) FWD(int, setgid,(unsigned a),(a))
FWD(void *, getpwent,(void),()) FWDV(endpwent,(void),())
FWD(void *, getgrent,(void),()) FWD(void *, getgrnam,(const char*a),(a)) FWDV(endgrent,(void),())
FWD(int, getitimer,(int a,void*b),(a,b)) FWD(int, setitimer,(int a,const void*b,void*c),(a,b,c))
FWD(int, getrlimit,(int a,void*b),(a,b)) FWD(int, setrlimit,(int a,const void*b),(a,b))
FWD(long, ulimit,(int a,long b),(a,b)) FWD(long, sysconf,(int a),(a))
FWD(int, pause,(void),()) FWD(int, wait3,(int*a,int b,void*c),(a,b,c))
FWD(void *, __bsd_signal,(int a,void*b),(a,b)) FWDV(srand,(unsigned a),(a))
FWD(unsigned, usleep,(unsigned a),(a))
/* file / fs */
FWD(int, creat,(const char*a,unsigned b),(a,b))
FWD(int, chown,(const char*a,unsigned b,unsigned c),(a,b,c))
FWD(int, link,(const char*a,const char*b),(a,b))
FWD(long, readlink,(const char*a,char*b,size_t c),(a,b,c))
FWD(int, lockf,(int a,int b,long c),(a,b,c))
extern int mkfifo(const char *, unsigned);
/* WP creates its exec-message FIFOs via the ancient libc5 mknod(S_IFIFO,...)
 * convention, which modern glibc/kernel reject with EINVAL. Route FIFO
 * creation to mkfifo() (the correct modern API). Preserve perms, defaulting
 * to 0666 when WP passes none (so the peer processes can open the FIFO). */
#define WP_S_IFMT  0xF000u
#define WP_S_IFIFO 0x1000u
int mknod(const char *a, unsigned b, unsigned c) {
    int r;
    char _rbuf[512]; a = r5_wpexc_rewrite(a, _rbuf, sizeof _rbuf);
    if ((b & WP_S_IFMT) == WP_S_IFIFO) {
        unsigned perm = b & 0777; if (!perm) perm = 0666;
        r = mkfifo(a, perm); SYNC_ERRNO();
        logkv("mknod->mkfifo", a); logint("  perm", perm); logint("  ret", r);
        if (r < 0) logint("  errno", *__errno_location());
        return r;
    }
    static int (*fn)(const char *, unsigned, unsigned);
    if (!fn) fn = (int (*)(const char *, unsigned, unsigned)) dlsym(RTLD_NEXT, "mknod");
    r = fn(a, b, c); SYNC_ERRNO();
    logkv("mknod", a); logint("  mknod mode", b); logint("  mknod ret", r);
    if (r < 0) logint("  mknod errno", *__errno_location());
    return r;
}
int _xmknod(int a, const char *b, unsigned c, void *d) {
    char _rbuf[512]; b = r5_wpexc_rewrite(b, _rbuf, sizeof _rbuf);
    if ((c & WP_S_IFMT) == WP_S_IFIFO) {
        unsigned perm = c & 0777; if (!perm) perm = 0666;
        int r = mkfifo(b, perm); SYNC_ERRNO();
        logkv("_xmknod->mkfifo", b); logint("  perm", perm); logint("  ret", r);
        return r;
    }
    static int (*fn)(int, const char *, unsigned, void *);
    if (!fn) fn = (int (*)(int, const char *, unsigned, void *)) dlsym(RTLD_NEXT, "_xmknod");
    int r = fn(a, b, c, d); SYNC_ERRNO();
    logkv("_xmknod", b); logint("  _xmknod mode", c); logint("  _xmknod ret", r);
    if (r < 0) logint("  _xmknod errno", *__errno_location());
    return r;
}
FWD(char *, ttyname,(int a),(a))
FWD(int, statfs,(const char*a,void*b),(a,b))
FWD(char *, getpass,(const char*a),(a))
/* time */
FWD(char *, asctime,(const void*a),(a))
FWD(char *, ctime,(const long*a),(a))
FWD(long, mktime,(void*a),(a))
/* signals (sigset_t/sigaction structs differ libc5<->glibc; forward, revisit) */
FWD(int, sigaction,(int a,const void*b,void*c),(a,b,c))
FWD(int, sigaddset,(void*a,int b),(a,b))
FWD(int, sigemptyset,(void*a),(a))
FWD(int, sigprocmask,(int a,const void*b,void*c),(a,b,c))
FWD(int, __sigjmp_save,(void*a,int b),(a,b))
/* siglongjmp() is declared noreturn; forward then mark unreachable. */
void siglongjmp(void *a, int b) {
    static void (*fn)(void *, int);
    if (!fn) fn = (void (*)(void *, int)) dlsym(RTLD_NEXT, "siglongjmp");
    PRE_ERRNO();
    fn(a, b);
    __builtin_unreachable();
}
/* termios (struct differs; forward, revisit) */
FWD(int, cfgetospeed,(const void*a),(a))
FWD(int, tcflush,(int a,int b),(a,b))
FWD(int, tcgetattr,(int a,void*b),(a,b))
FWD(int, tcsetattr,(int a,int b,const void*c),(a,b,c))

/* execlp: repack varargs -> execvp */
extern int execvp(const char *, char *const *);
int execlp(const char *file, const char *arg0, ...) {
    char *argv[64]; int n = 0; argv[n++] = (char *)arg0;
    va_list ap; va_start(ap, arg0);
    while (n < 63 && (argv[n] = va_arg(ap, char *)) != 0) n++;
    argv[n] = 0; va_end(ap);
    return execvp(file, argv);
}

/* ---- varargs (resolved + forwarded explicitly) --------------------------- */
int open(const char *path, int flags, ...) {
    unsigned mode = 0;
    va_list ap; va_start(ap, flags); mode = va_arg(ap, unsigned); va_end(ap);
    static int (*fn)(const char *, int, unsigned);
    if (!fn) fn = (int (*)(const char *, int, unsigned)) dlsym(RTLD_NEXT, "open");
    char _rbuf[512]; const char *rpath = r5_wpexc_rewrite(path, _rbuf, sizeof _rbuf);
    int r = fn(rpath, flags, mode);
    /* skip our own log/proc paths to avoid logkv->open recursion */
    if (!startswith(path, "/tmp/wpshim.log") && !startswith(path, "/proc/self/cmdline")) {
        SYNC_ERRNO(); logkv("open", path);
        logint("  open flags", flags); logint("  open ret", r);
        if (r < 0) logint("  open errno", *__errno_location());
        /* remember the wp.drs fd to trace its reads/seeks */
        { extern int g_drs_fd; const char *p = path, *tail = path;
          while (*p) { if (*p == '/') tail = p + 1; p++; }
          if (r >= 0 && startswith(tail, "wp.drs")) { g_drs_fd = r; logint("  [tracking wp.drs fd]", r); }
          if (r >= 0 && g_ipc_n < 16 &&
              (startswith(tail,"excmsg8")||startswith(tail,"_000_")||startswith(tail,"_UNX_")||startswith(tail,"_WP_")))
              { g_ipc_fds[g_ipc_n++] = r; logkv("  [tracking IPC chan]", tail); logint("    fd", r); } }
    }
    /* CUPS mode: tag the spooler's %!PS temp so write() tees its bytes into memory. */
    if (r >= 0 && r5_cups_enabled() && r5cap_is_ps_temp(path)) r5cap_open(path, r);
    return r;
}
/* openat/mknodat/unlinkat: not part of the libc5 ABI (WP never calls them), but
 * interposed for completeness so any *at() caller that resolves through the shim
 * gets the same per-instance rewrite. Gated identically via wpexc_rewrite. */
int openat(int dirfd, const char *path, int flags, ...) {
    unsigned mode = 0;
    va_list ap; va_start(ap, flags); mode = va_arg(ap, unsigned); va_end(ap);
    static int (*fn)(int, const char *, int, unsigned);
    if (!fn) fn = (int (*)(int, const char *, int, unsigned)) dlsym(RTLD_NEXT, "openat");
    char buf[512]; const char *p = r5_wpexc_rewrite(path, buf, sizeof buf);
    PRE_ERRNO(); int r = fn(dirfd, p, flags, mode); SYNC_ERRNO(); return r;
}
int mknodat(int dirfd, const char *path, unsigned mode, unsigned dev) {
    static int (*fn)(int, const char *, unsigned, unsigned);
    if (!fn) fn = (int (*)(int, const char *, unsigned, unsigned)) dlsym(RTLD_NEXT, "mknodat");
    char buf[512]; const char *p = r5_wpexc_rewrite(path, buf, sizeof buf);
    PRE_ERRNO(); int r = fn(dirfd, p, mode, dev); SYNC_ERRNO(); return r;
}
int unlinkat(int dirfd, const char *path, int flags) {
    static int (*fn)(int, const char *, int);
    if (!fn) fn = (int (*)(int, const char *, int)) dlsym(RTLD_NEXT, "unlinkat");
    char buf[512]; const char *p = r5_wpexc_rewrite(path, buf, sizeof buf);
    PRE_ERRNO(); int r = fn(dirfd, p, flags); SYNC_ERRNO(); return r;
}
int fcntl(int fd, int cmd, ...) {
    va_list ap; va_start(ap, cmd); void *arg = va_arg(ap, void *); va_end(ap);
    static int (*fn)(int, int, void *);
    if (!fn) fn = (int (*)(int, int, void *)) dlsym(RTLD_NEXT, "fcntl");
    int r = fn(fd, cmd, arg);
    SYNC_ERRNO();
    /* F_GETLK=5 F_SETLK=6 F_SETLKW=7 : log locking attempts + result */
    if (cmd >= 5 && cmd <= 7) {
        logint("fcntl LOCK cmd", cmd); logint("  fcntl fd", fd); logint("  fcntl ret", r);
        if (r < 0) logint("  fcntl errno", *__errno_location());
    }
    return r;
}
int ioctl(int fd, unsigned long req, ...) {
    va_list ap; va_start(ap, req); void *arg = va_arg(ap, void *); va_end(ap);
    static int (*fn)(int, unsigned long, void *);
    if (!fn) fn = (int (*)(int, unsigned long, void *)) dlsym(RTLD_NEXT, "ioctl");
    return fn(fd, req, arg);
}
int sprintf(char *s, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsprintf(s, fmt, ap); va_end(ap);
    if (startswith(fmt, "%s%s") || startswith(fmt, "local") || startswith(fmt, "/tmp") ||
        startswith(fmt, "unix") || startswith(s, "local") || startswith(s, "/tmp/.X"))
        { logkv("sprintf fmt", fmt); logkv("sprintf out", s); }
    return n;
}
int sscanf(const char *s, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsscanf(s, fmt, ap); va_end(ap);
    logkv("sscanf in", s); logkv("sscanf fmt", fmt);
    return n;
}
