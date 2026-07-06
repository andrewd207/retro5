/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* libc5.h - Linux libc5 (a.out-era GNU libc 5.x) ABI layouts.
 *
 * These structs must match libc5's binary layout EXACTLY, because WordPerfect
 * was compiled against libc5 headers and inlined macros (getc/putc, stat field
 * access) that read these structures at fixed offsets. Confirmed against the
 * Ghidra decompile of wpdecom (which accessed FILE->_IO_read_ptr etc.) and the
 * disassembly of veruxkey/wpdecom (struct stat: st_size @ 0x14, st_mode @ 0x8).
 *
 * i386, 32-bit. Do not reorder fields.
 */
#ifndef WPLIBC5_H
#define WPLIBC5_H

#include <stddef.h>

/* ---- libc5 libio FILE (the _IO_FILE lineage shared with early glibc) ------ */
/* Offsets that WP's inlined getc/putc touch: _flags@0, _IO_read_ptr@4,
 * _IO_read_end@8, _IO_write_ptr@20, _IO_write_end@24, _fileno@56. */
typedef struct _lc5_FILE {
    int    _flags;            /* 0  */
    char  *_IO_read_ptr;      /* 4  */
    char  *_IO_read_end;      /* 8  */
    char  *_IO_read_base;     /* 12 */
    char  *_IO_write_base;    /* 16 */
    char  *_IO_write_ptr;     /* 20 */
    char  *_IO_write_end;     /* 24 */
    char  *_IO_buf_base;      /* 28 */
    char  *_IO_buf_end;       /* 32 */
    char  *_IO_save_base;     /* 36 */
    char  *_IO_backup_base;   /* 40 */
    char  *_IO_save_end;      /* 44 */
    void  *_markers;          /* 48 */
    struct _lc5_FILE *_chain; /* 52 */
    int    _fileno;           /* 56 */
    int    _blksize;          /* 60 */
    long   _offset;           /* 64 */
    unsigned short _cur_column;/*68 */
    signed char   _vtable_offset;/*70*/
    char   _shortbuf[1];      /* 71 */
    void  *_lock;             /* 72 */
    /* trailing pad so our allocation is never smaller than libc5's FILE */
    char   _pad[64];
} LC5_FILE;

/* _flags bits we care about (libio) */
#define LC5_EOF_SEEN   0x0010
#define LC5_ERR_SEEN   0x0020
#define LC5_IS_READING 0x0004   /* informational only; WP fast path ignores */

/* ---- libc5 struct stat (i386, 16-bit dev/uid/gid, 32-bit ino/size) -------- */
struct lc5_stat {
    unsigned short st_dev;     /* 0  */
    unsigned short __pad1;     /* 2  */
    unsigned long  st_ino;     /* 4  */
    unsigned short st_mode;    /* 8  */
    unsigned short st_nlink;   /* 10 */
    unsigned short st_uid;     /* 12 */
    unsigned short st_gid;     /* 14 */
    unsigned short st_rdev;    /* 16 */
    unsigned short __pad2;     /* 18 */
    unsigned long  st_size;    /* 20 */
    unsigned long  st_blksize; /* 24 */
    unsigned long  st_blocks;  /* 28 */
    unsigned long  atime_;     /* 32  (st_atime is a glibc macro, don't use it) */
    unsigned long  __unused1;  /* 36 */
    unsigned long  mtime_;     /* 40 */
    unsigned long  __unused2;  /* 44 */
    unsigned long  ctime_;     /* 48 */
    unsigned long  __unused3;  /* 52 */
    unsigned long  __unused4;  /* 56 */
    unsigned long  __unused5;  /* 60 */
};                             /* size 64 */

/* ---- libc5 struct dirent (i386) ------------------------------------------- */
struct lc5_dirent {
    long           d_ino;      /* 0  */
    long           d_off;      /* 4  */
    unsigned short d_reclen;   /* 8  */
    char           d_name[256];/* 10 */
};

/* ---- libc5 struct passwd (16-bit uid/gid) --------------------------------- */
struct lc5_passwd {
    char          *pw_name;    /* 0  */
    char          *pw_passwd;  /* 4  */
    unsigned short pw_uid;     /* 8  */
    unsigned short pw_gid;     /* 10 */
    char          *pw_gecos;   /* 12 */
    char          *pw_dir;     /* 16 */
    char          *pw_shell;   /* 20 */
};

/* stdio exports implemented in stdio5.c */
LC5_FILE *lc5_stdout(void);   /* internal: fd 1 target for printf */

#endif /* WPLIBC5_H */
