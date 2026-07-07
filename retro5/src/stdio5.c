/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* stdio5.c - libc5-layout stdio for WordPerfect.
 *
 * WP inlined its getc/putc macros at compile time, so its code reads
 * FILE->_IO_read_ptr/_end and _IO_write_ptr/_end directly and calls
 * __uflow/__overflow on the buffer boundary. We therefore CANNOT forward to
 * glibc stdio (different FILE layout). Instead we implement a small buffered
 * stdio over raw read()/write(), returning FILE* whose layout is LC5_FILE.
 *
 * NOTE: no <stdio.h> here — we must not pull in glibc's FILE definition.
 */
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "libc5.h"

extern void *__libc_malloc(size_t);
extern void  __libc_free(void *);
extern int   vsnprintf(char *, size_t, const char *, va_list);

#define BUFSZ 8192
#define LC5_EOF (-1)

/* forward decls (definitions appear later in this file) */
LC5_FILE *fopen(const char *, const char *);
int  fseek(LC5_FILE *, long, int);
long ftell(LC5_FILE *);

/* ---- internal helpers ----------------------------------------------------- */
static long write_all(int fd, const char *p, long n) {
    long done = 0;
    while (done < n) {
        long w = write(fd, p + done, n - done);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) break;
        done += w;
    }
    return done;
}

/* write() whose result we deliberately discard (best-effort diagnostics). */
static void iwrite(int fd, const void *p, size_t n) {
    ssize_t r = write(fd, p, n);
    (void)r;
}

static LC5_FILE *new_file(int fd, int writing) {
    LC5_FILE *fp = (LC5_FILE *)__libc_malloc(sizeof(LC5_FILE));
    char *buf = (char *)__libc_malloc(BUFSZ);
    if (!fp || !buf) { if (fp) __libc_free(fp); if (buf) __libc_free(buf); return 0; }
    __builtin_memset(fp, 0, sizeof(*fp));
    fp->_fileno = fd;
    fp->_blksize = BUFSZ;
    fp->_IO_buf_base = buf;
    fp->_IO_buf_end  = buf + BUFSZ;
    if (writing) {
        fp->_IO_write_base = buf;
        fp->_IO_write_ptr  = buf;
        fp->_IO_write_end  = buf + BUFSZ;
    } else {
        /* empty read buffer -> first access triggers __uflow */
        fp->_IO_read_base = buf;
        fp->_IO_read_ptr  = buf;
        fp->_IO_read_end  = buf;
    }
    return fp;
}

/* ---- the two functions WP's inlined macros call --------------------------- */
int __uflow(LC5_FILE *fp) {
    if (fp->_IO_read_ptr < fp->_IO_read_end)
        return (unsigned char)*fp->_IO_read_ptr++;
    long n;
    if (fp->_IO_buf_base == 0) {         /* unbuffered (e.g. copy-reloc'd stdin) */
        unsigned char ch;
        do { n = read(fp->_fileno, &ch, 1); } while (n < 0 && errno == EINTR);
        if (n <= 0) { fp->_flags |= LC5_EOF_SEEN; return LC5_EOF; }
        return ch;
    }
    do { n = read(fp->_fileno, fp->_IO_buf_base, BUFSZ); }
    while (n < 0 && errno == EINTR);
    if (n <= 0) { fp->_flags |= LC5_EOF_SEEN; return LC5_EOF; }
    fp->_IO_read_base = fp->_IO_buf_base;
    fp->_IO_read_end  = fp->_IO_buf_base + n;
    fp->_IO_read_ptr  = fp->_IO_buf_base + 1;
    return (unsigned char)fp->_IO_buf_base[0];
}

int __overflow(LC5_FILE *fp, int c) {
    if (fp->_IO_write_base == 0) {          /* unbuffered (e.g. copy-reloc'd stderr) */
        if (c != LC5_EOF) { char ch = (char)c; iwrite(fp->_fileno, &ch, 1); }
        return c & 0xff;
    }
    long n = fp->_IO_write_ptr - fp->_IO_write_base;
    if (n > 0) {
        if (write_all(fp->_fileno, fp->_IO_write_base, n) != n) {
            fp->_flags |= LC5_ERR_SEEN; return LC5_EOF;
        }
    }
    fp->_IO_write_ptr = fp->_IO_write_base;
    if (c != LC5_EOF) *fp->_IO_write_ptr++ = (char)c;
    return c & 0xff;
}

/* ---- open / close / flush ------------------------------------------------- */
LC5_FILE *fopen(const char *path, const char *mode) {
    int flags = 0, writing = 0;
    switch (mode[0]) {
        case 'r': flags = O_RDONLY; if (mode[1]=='+'||(mode[1]=='b'&&mode[2]=='+')) flags = O_RDWR; break;
        case 'w': flags = O_WRONLY|O_CREAT|O_TRUNC; writing = 1; break;
        case 'a': flags = O_WRONLY|O_CREAT|O_APPEND; writing = 1; break;
        default:  return 0;
    }
    int fd = open(path, flags, 0666);
    if (fd < 0) return 0;
    LC5_FILE *fp = new_file(fd, writing);
    if (!fp) { close(fd); return 0; }
    return fp;
}

/* Large-file aliases: modern libs (libX11 locale code) call fopen64/freopen64.
 * We must interpose these too, else they get a glibc FILE while their
 * fgets/fread bind to our stdio -> reads a NULL buffer -> EFAULT infinite loop. */
LC5_FILE *fopen64(const char *path, const char *mode) { return fopen(path, mode); }
int      fseeko64(LC5_FILE *fp, long long off, int w) { return fseek(fp, (long)off, w); }
long long ftello64(LC5_FILE *fp) { return ftell(fp); }

int fflush(LC5_FILE *fp) {
    if (!fp) return 0;
    long n = fp->_IO_write_ptr - fp->_IO_write_base;
    if (n > 0) {
        if (write_all(fp->_fileno, fp->_IO_write_base, n) != n) return LC5_EOF;
        fp->_IO_write_ptr = fp->_IO_write_base;
    }
    return 0;
}

int fclose(LC5_FILE *fp) {
    if (!fp) return 0;
    fflush(fp);
    int r = close(fp->_fileno);
    if (fp->_IO_buf_base) __libc_free(fp->_IO_buf_base);
    __libc_free(fp);
    return r;
}

/* fseek/ftell: needed not just by WP but by any modern lib (e.g. libXcursor)
 * that got one of our FILEs from the interposed fopen. */
int fseek(LC5_FILE *fp, long offset, int whence) {
    if (fflush(fp) != 0) return -1;
    /* account for buffered-but-unread data when seeking relative */
    if (whence == SEEK_CUR)
        offset -= (fp->_IO_read_end - fp->_IO_read_ptr);
    if (lseek(fp->_fileno, offset, whence) < 0) return -1;
    fp->_IO_read_ptr = fp->_IO_read_end = fp->_IO_read_base = fp->_IO_buf_base;
    fp->_flags &= ~(LC5_EOF_SEEN | LC5_ERR_SEEN);
    return 0;
}

long ftell(LC5_FILE *fp) {
    long pos = lseek(fp->_fileno, 0, SEEK_CUR);
    if (pos < 0) return -1;
    pos -= (fp->_IO_read_end - fp->_IO_read_ptr);   /* unread buffered bytes */
    return pos;
}

LC5_FILE *freopen(const char *path, const char *mode, LC5_FILE *fp) {
    if (!fp) return fopen(path, mode);
    fflush(fp);
    if (fp->_fileno >= 0) close(fp->_fileno);
    int flags = 0, writing = 0;
    switch (mode[0]) {
        case 'r': flags = O_RDONLY; break;
        case 'w': flags = O_WRONLY | O_CREAT | O_TRUNC; writing = 1; break;
        case 'a': flags = O_WRONLY | O_CREAT | O_APPEND; writing = 1; break;
        default:  return 0;
    }
    int fd = open(path, flags, 0666);
    if (fd < 0) return 0;
    fp->_fileno = fd;
    if (!fp->_IO_buf_base) {
        fp->_IO_buf_base = (char *)__libc_malloc(BUFSZ);
        fp->_IO_buf_end = fp->_IO_buf_base + BUFSZ;
    }
    if (writing) {
        fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
        fp->_IO_write_end = fp->_IO_buf_base + BUFSZ;
        fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end = 0;
    } else {
        fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end = fp->_IO_buf_base;
        fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = 0;
    }
    fp->_flags = 0;
    return fp;
}

/* perror: straight to fd 2, using our libc5 _errno */
extern char *strerror(int);
extern int _errno;
void perror(const char *s) {
    char *e = strerror(_errno);
    if (s && *s) { iwrite(2, s, __builtin_strlen(s)); iwrite(2, ": ", 2); }
    if (e) iwrite(2, e, __builtin_strlen(e));
    iwrite(2, "\n", 1);
}

void rewind(LC5_FILE *fp) {
    fflush(fp);
    lseek(fp->_fileno, 0, SEEK_SET);
    fp->_IO_read_ptr = fp->_IO_read_end = fp->_IO_read_base = fp->_IO_buf_base;
    fp->_flags &= ~(LC5_EOF_SEEN | LC5_ERR_SEEN);
}

/* ---- read side ------------------------------------------------------------ */
int fgetc(LC5_FILE *fp) {
    if (fp->_IO_read_ptr < fp->_IO_read_end)
        return (unsigned char)*fp->_IO_read_ptr++;
    return __uflow(fp);
}

int ungetc(int c, LC5_FILE *fp) {
    if (c == LC5_EOF) return LC5_EOF;
    if (fp->_IO_read_ptr > fp->_IO_read_base)
        return (unsigned char)(*--fp->_IO_read_ptr = (char)c);
    return LC5_EOF; /* no room (rare for WP) */
}

size_t fread(void *ptr, size_t size, size_t nmemb, LC5_FILE *fp) {
    size_t total = size * nmemb, got = 0;
    char *out = (char *)ptr;
    if (size == 0) return 0;
    while (got < total) {
        if (fp->_IO_read_ptr >= fp->_IO_read_end) {
            int c = __uflow(fp);
            if (c == LC5_EOF) break;
            out[got++] = (char)c;
            continue;
        }
        long avail = fp->_IO_read_end - fp->_IO_read_ptr;
        long want  = (long)(total - got);
        long n = avail < want ? avail : want;
        __builtin_memcpy(out + got, fp->_IO_read_ptr, n);
        fp->_IO_read_ptr += n;
        got += n;
    }
    return got / size;
}

char *fgets(char *s, int size, LC5_FILE *fp) {
    int i = 0;
    if (size <= 0) return 0;
    while (i < size - 1) {
        int c = fgetc(fp);
        if (c == LC5_EOF) { if (i == 0) return 0; break; }
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    s[i] = '\0';
    return s;
}

/* ---- write side ----------------------------------------------------------- */
size_t fwrite(const void *ptr, size_t size, size_t nmemb, LC5_FILE *fp) {
    size_t total = size * nmemb, put = 0;
    const char *in = (const char *)ptr;
    if (size == 0) return 0;
    /* unbuffered stream (e.g. copy-reloc'd stderr, _IO_write_base==0): write
     * straight through — the buffered loop below can't make progress with no
     * buffer and would spin forever. */
    if (fp->_IO_write_base == 0) {
        long w = write_all(fp->_fileno, in, (long)total);
        if (w < 0) { fp->_flags |= LC5_ERR_SEEN; return 0; }
        return (size_t)w / size;
    }
    while (put < total) {
        if (fp->_IO_write_ptr >= fp->_IO_write_end)
            if (__overflow(fp, LC5_EOF) == LC5_EOF) break;
        long room = fp->_IO_write_end - fp->_IO_write_ptr;
        long want = (long)(total - put);
        long n = room < want ? room : want;
        __builtin_memcpy(fp->_IO_write_ptr, in + put, n);
        fp->_IO_write_ptr += n;
        put += n;
    }
    return put / size;
}

int fputs(const char *s, LC5_FILE *fp) {
    size_t len = __builtin_strlen(s);
    return fwrite(s, 1, len, fp) == len ? 0 : LC5_EOF;
}

/* ---- formatted output ----------------------------------------------------- */
/* stdout/stdin are the copy-relocatable, UNBUFFERED libc5 structs (data5.c), so
 * our own printf/scanf and the program's inlined putchar/getchar share one
 * consistent stream each -- fwrite's unbuffered path writes each chunk with a
 * single write(), so this is not slow. */
extern LC5_FILE _IO_stdout_;
extern LC5_FILE _IO_stdin_;

LC5_FILE *lc5_stdout(void) {
    return &_IO_stdout_;
}

int fprintf(LC5_FILE *fp, const char *fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return n;
    if ((size_t)n > sizeof(buf)) n = sizeof(buf);
    fwrite(buf, 1, n, fp);
    return n;
}

int printf(const char *fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return n;
    if ((size_t)n > sizeof(buf)) n = sizeof(buf);
    LC5_FILE *o = lc5_stdout();
    fwrite(buf, 1, n, o);
    fflush(o);
    return n;
}

/* Fortified variants: modern libs (libXt's XtWarning, etc.) call these on our
 * interposed FILEs. Route them through our stdio so they operate on LC5_FILE. */
int __fprintf_chk(LC5_FILE *fp, int flag, const char *fmt, ...) {
    char buf[4096]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    if (n < 0) return n;
    if ((size_t)n > sizeof(buf)) n = sizeof(buf);
    fwrite(buf, 1, n, fp);
    return n;
}
int __printf_chk(int flag, const char *fmt, ...) {
    char buf[4096]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    if (n < 0) return n;
    if ((size_t)n > sizeof(buf)) n = sizeof(buf);
    LC5_FILE *o = lc5_stdout();
    fwrite(buf, 1, n, o); fflush(o);
    return n;
}

/* ==== suite-wide stdio additions (all operate on LC5_FILE) ================= */
extern int vsscanf(const char *, const char *, va_list);
extern int getpid(void);
extern int unlink(const char *);
extern int pipe(int[2]);
extern int fork(void);
extern int dup2(int, int);
extern void _exit(int);
extern int execv(const char *, char *const *);
extern int waitpid(int, int *, int);

int  fileno(LC5_FILE *fp)   { return fp->_fileno; }
int  feof(LC5_FILE *fp)     { return (fp->_flags & LC5_EOF_SEEN) ? 1 : 0; }
int  ferror(LC5_FILE *fp)   { return (fp->_flags & LC5_ERR_SEEN) ? 1 : 0; }
void clearerr(LC5_FILE *fp) { fp->_flags &= ~(LC5_EOF_SEEN | LC5_ERR_SEEN); }
int  setvbuf(LC5_FILE *fp, char *b, int m, size_t s) { (void)fp;(void)b;(void)m;(void)s; return 0; }
void setlinebuf(LC5_FILE *fp) { (void)fp; }

int fputc(int c, LC5_FILE *fp) {
    if (fp->_IO_write_ptr && fp->_IO_write_ptr < fp->_IO_write_end)
        return (unsigned char)(*fp->_IO_write_ptr++ = (char)c);
    return __overflow(fp, (unsigned char)c);
}

LC5_FILE *fdopen(int fd, const char *mode) {
    return new_file(fd, (mode[0] == 'w' || mode[0] == 'a'));
}

int vfprintf(LC5_FILE *fp, const char *fmt, va_list ap) {
    char buf[4096]; int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) return n;
    if ((size_t)n > sizeof(buf)) n = sizeof(buf);
    fwrite(buf, 1, n, fp); return n;
}
/* Forward to glibc's real vsprintf. Do NOT use vsnprintf(s,(size_t)-1,...):
 * on 32-bit, buf_end = s + 0xFFFFFFFF overflows the pointer and glibc
 * truncates the output (silently dropping trailing args). */
extern void *dlsym(void *, const char *);
#define WP_RTLD_NEXT ((void *)-1l)
int vsprintf(char *s, const char *fmt, va_list ap) {
    static int (*fn)(char *, const char *, va_list);
    if (!fn) fn = (int (*)(char *, const char *, va_list)) dlsym(WP_RTLD_NEXT, "vsprintf");
    return fn(s, fmt, ap);
}
int snprintf(char *s, size_t sz, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); int n = vsnprintf(s, sz, fmt, ap); va_end(ap); return n;
}
int fscanf(LC5_FILE *fp, const char *fmt, ...) {          /* line-based best effort */
    char line[4096]; if (!fgets(line, sizeof(line), fp)) return -1;
    va_list ap; va_start(ap, fmt); int r = vsscanf(line, fmt, ap); va_end(ap); return r;
}
char *gets(char *s) {
    int i = 0; char c;
    for (;;) {
        long n = read(0, &c, 1);
        if (n <= 0) { if (i == 0) return 0; break; }
        if (c == '\n') break;
        s[i++] = c;
    }
    s[i] = '\0'; return s;
}

static int _tmpctr = 0;
char *tmpnam(char *s) {
    static char buf[64]; char *o = s ? s : buf;
    snprintf(o, 64, "/tmp/wpt%d_%d", getpid(), _tmpctr++); return o;
}
char *tempnam(const char *dir, const char *pfx) {
    char *o = (char *)__libc_malloc(160);
    snprintf(o, 160, "%s/%s%d_%d", dir ? dir : "/tmp", pfx ? pfx : "wp", getpid(), _tmpctr++);
    return o;
}
LC5_FILE *tmpfile(void) {
    char nm[64]; snprintf(nm, 64, "/tmp/wptf%d_%d", getpid(), _tmpctr++);
    int fd = open(nm, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 0;
    unlink(nm);
    return new_file(fd, 1);
}

static int _popen_pid[256];
LC5_FILE *popen(const char *cmd, const char *mode) {
    int reading = (mode[0] == 'r'), fds[2];
    if (pipe(fds) < 0) return 0;
    int pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return 0; }
    if (pid == 0) {
        if (reading) dup2(fds[1], 1); else dup2(fds[0], 0);
        close(fds[0]); close(fds[1]);
        char *argv[] = { (char *)"/bin/sh", (char *)"-c", (char *)cmd, 0 };
        execv("/bin/sh", argv); _exit(127);
    }
    int myfd = reading ? fds[0] : fds[1];
    close(reading ? fds[1] : fds[0]);
    if (myfd >= 0 && myfd < 256) _popen_pid[myfd] = pid;
    return new_file(myfd, !reading);
}
int pclose(LC5_FILE *fp) {
    int fd = fp->_fileno, status = 0;
    int pid = (fd >= 0 && fd < 256) ? _popen_pid[fd] : 0;
    fclose(fp);
    if (pid > 0) waitpid(pid, &status, 0);
    return status;
}
