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
FWDV(abort,  (void), ())
/* exit: glibc's exit runs _IO_cleanup (flush all glibc streams), which
 * segfaults given our interposed/libc5-layout FILEs. Run the registered
 * atexit/__cxa_atexit handlers ourselves, then _exit — skipping the crash. */
extern void __cxa_finalize(void *);
extern void _exit(int);
void exit(int code) {
    static int busy = 0;
    if (!busy) { busy = 1; __cxa_finalize(0); }
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
FWD(int,   geteuid,(void), ())
FWD(int,   getegid,(void), ())
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
FWD(int,   access,  (const char *a, int b), (a, b))
FWD(int,   chdir,   (const char *a), (a))
FWD(int,   chmod,   (const char *a, unsigned b), (a, b))
FWD(int,   fchmod,  (int a, unsigned b), (a, b))
FWD(int,   mkdir,   (const char *a, unsigned b), (a, b))
FWD(int,   rmdir,   (const char *a), (a))
FWD(int,   unlink,  (const char *a), (a))
FWD(int,   rename,  (const char *a, const char *b), (a, b))
FWD(int,   close,   (int a), (a))
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
FWDV(siglongjmp,(void*a,int b),(a,b))
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
    int r = fn(path, flags, mode);
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
    return r;
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
