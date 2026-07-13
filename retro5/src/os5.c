/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* os5.c - libc5 ABI translations that need struct remapping:
 *   stat family, directory reading, passwd, and libc5 startup glue.
 */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include "libc5.h"

extern void *__libc_malloc(size_t);
extern void  __libc_free(void *);

/* WP reads its own copy-relocated `_errno` (non-TLS), but glibc's stat() sets
 * glibc's TLS errno. WP's file-open pre-check (fileop_precheck_errno @0x08513170)
 * does `_xstat(); if (errno != ENOENT) fail`, so a stat that fails with ENOENT
 * (e.g. saving a file that doesn't exist yet) MUST leave WP's _errno == ENOENT.
 * Without this sync WP sees a stale _errno (0) != 2 and spuriously aborts the
 * save with "An error occurred opening the file". */
extern int _errno;
#define SYNC_ERRNO() (_errno = errno)

/* ---- stat family: modern struct stat -> libc5 struct lc5_stat ------------- */
static void xlate_stat(const struct stat *s, struct lc5_stat *b) {
    __builtin_memset(b, 0, sizeof(*b));
    b->st_dev     = (unsigned short)s->st_dev;
    b->st_ino     = (unsigned long)s->st_ino;
    b->st_mode    = (unsigned short)s->st_mode;
    b->st_nlink   = (unsigned short)s->st_nlink;
    b->st_uid     = (unsigned short)s->st_uid;
    b->st_gid     = (unsigned short)s->st_gid;
    b->st_rdev    = (unsigned short)s->st_rdev;
    b->st_size    = (unsigned long)s->st_size;
    b->st_blksize = (unsigned long)s->st_blksize;
    b->st_blocks  = (unsigned long)s->st_blocks;
    b->atime_     = (unsigned long)s->st_atime;
    b->mtime_     = (unsigned long)s->st_mtime;
    b->ctime_     = (unsigned long)s->st_ctime;
}

/* Per-instance print-server path rewrite (defined in forward.c). MUST be applied
 * here too: WP checks/releases its .wpexc8.LCK lock via _xstat/_lxstat, so if we
 * rewrite the open() but not the stat(), xwp stats the un-rewritten name, sees it
 * absent, and never releases the lock -> wpexc hangs and dies with "error 21". */
extern const char *r5_wpexc_rewrite(const char *path, char *buf, size_t bufsz);

int _xstat(int ver, const char *path, struct lc5_stat *b) {
    (void)ver; struct stat s;
    char rb[512]; path = r5_wpexc_rewrite(path, rb, sizeof rb);
    if (stat(path, &s) < 0) { SYNC_ERRNO(); return -1; }
    xlate_stat(&s, b); return 0;
}
int _lxstat(int ver, const char *path, struct lc5_stat *b) {
    (void)ver; struct stat s;
    char rb[512]; path = r5_wpexc_rewrite(path, rb, sizeof rb);
    if (lstat(path, &s) < 0) { SYNC_ERRNO(); return -1; }
    xlate_stat(&s, b); return 0;
}
int _fxstat(int ver, int fd, struct lc5_stat *b) {
    (void)ver; struct stat s;
    if (fstat(fd, &s) < 0) { SYNC_ERRNO(); return -1; }
    xlate_stat(&s, b); return 0;
}

/* ---- directories: raw getdents64 -> libc5 struct lc5_dirent --------------- */
typedef struct {
    int  fd;
    long bufpos, buflen;
    struct lc5_dirent ent;
    char buf[4096];
} LC5_DIR;

struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

void *opendir(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return 0;
    LC5_DIR *d = (LC5_DIR *)__libc_malloc(sizeof(LC5_DIR));
    if (!d) { close(fd); return 0; }
    d->fd = fd; d->bufpos = d->buflen = 0;
    return d;
}

struct lc5_dirent *readdir(void *dirp) {
    LC5_DIR *d = (LC5_DIR *)dirp;
    if (!d) return 0;
    if (d->bufpos >= d->buflen) {
        long n = syscall(SYS_getdents64, d->fd, d->buf, sizeof(d->buf));
        if (n <= 0) return 0;
        d->buflen = n; d->bufpos = 0;
    }
    struct linux_dirent64 *e = (struct linux_dirent64 *)(d->buf + d->bufpos);
    d->bufpos += e->d_reclen;
    d->ent.d_ino = (long)e->d_ino;
    d->ent.d_off = (long)e->d_off;
    __builtin_strncpy(d->ent.d_name, e->d_name, sizeof(d->ent.d_name) - 1);
    d->ent.d_name[sizeof(d->ent.d_name) - 1] = '\0';
    d->ent.d_reclen = (unsigned short)(10 + __builtin_strlen(d->ent.d_name) + 1);
    return &d->ent;
}

int closedir(void *dirp) {
    LC5_DIR *d = (LC5_DIR *)dirp;
    if (!d) return -1;
    int r = close(d->fd);
    __libc_free(d);
    return r;
}

/* ---- passwd: glibc struct passwd -> libc5 struct lc5_passwd --------------- */
struct g_passwd {  /* mirror of glibc's layout (32-bit uid/gid) */
    char *pw_name; char *pw_passwd;
    unsigned int pw_uid; unsigned int pw_gid;
    char *pw_gecos; char *pw_dir; char *pw_shell;
};
static struct lc5_passwd pw5;

static struct lc5_passwd *xlate_pw(struct g_passwd *g) {
    if (!g) return 0;
    pw5.pw_name = g->pw_name;   pw5.pw_passwd = g->pw_passwd;
    pw5.pw_uid  = (unsigned short)g->pw_uid;
    pw5.pw_gid  = (unsigned short)g->pw_gid;
    pw5.pw_gecos = g->pw_gecos; pw5.pw_dir = g->pw_dir; pw5.pw_shell = g->pw_shell;
    return &pw5;
}
struct lc5_passwd *getpwnam(const char *name) {
    static struct g_passwd *(*real)(const char *);
    if (!real) real = (struct g_passwd *(*)(const char *))dlsym(RTLD_NEXT, "getpwnam");
    return xlate_pw(real(name));
}
struct lc5_passwd *getpwuid(unsigned int uid) {
    static struct g_passwd *(*real)(unsigned int);
    if (!real) real = (struct g_passwd *(*)(unsigned int))dlsym(RTLD_NEXT, "getpwuid");
    return xlate_pw(real(uid));
}

/* ---- libc5 startup glue --------------------------------------------------- */
void __libc_init(void) { /* args (argc,argv,envp) ignored; cdecl caller cleans */ }

void __setfpucw(unsigned short cw) { __asm__ __volatile__("fldcw %0" : : "m"(cw)); }

/* data symbol libc5 exported (current program break); WP may read it */
void *___brk_addr = 0;

/* _Xsetlocale -> setlocale */
char *_Xsetlocale(int category, const char *locale) {
    static char *(*real)(int, const char *);
    if (!real) real = (char *(*)(int, const char *))dlsym(RTLD_NEXT, "setlocale");
    return real(category, locale);
}
