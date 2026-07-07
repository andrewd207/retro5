/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* data5.c - libc5 DATA symbols that WP binaries copy-relocate (R_386_COPY)
 * and modern glibc no longer exports in a libc5-compatible form.
 *   widget classes  -> provided by modern libXt (not here)
 * So the shim only supplies the few below.
 */
#include "libc5.h"

/* libc5 errno (the R_386_COPY target; the `errno` alias is hidden in wpinstg
 * so glibc/libm bind to their own TLS errno instead — see hidesym.py). */
int _errno = 0;

/* default x87 FPU control word (round-to-nearest, double precision) */
unsigned short __fpu_control = 0x137f;

/* libc5 stderr FILE. Unbuffered: _IO_write_base==0 makes __overflow write
 * each byte straight to fd 2, so no pre-main buffer setup is needed (the
 * struct is copy-relocated into wpinstg's .bss before our constructors run). */
LC5_FILE _IO_stderr_ = { ._fileno = 2 };

/* libc5 stdout/stdin FILE, UNBUFFERED like _IO_stderr_ (_IO_write_base and
 * _IO_buf_base stay 0). Unbuffered is ESSENTIAL for a copy-relocated stream:
 * the program gets its OWN copy of the struct, and with no shared buffer there
 * is nothing to desync -- both copies read/write fd 0/1 directly. (A buffered
 * copy-relocated stdin/stdout would corrupt as the two copies' read/write
 * pointers diverge.) Providing these -- not letting them fall through to glibc's
 * incompatible _IO_2_1_ layout -- is what makes inlined putchar()/getchar() in a
 * console libc5 program touch the correct libc5 field offsets. */
LC5_FILE _IO_stdout_ = { ._fileno = 1 };
LC5_FILE _IO_stdin_  = { ._fileno = 0 };

/* __ctype_tolower / __ctype_toupper: pointers into 384-entry tables
 * (index range -128..255). glibc keeps the tables internal now, so we build
 * our own. The pointer values are copy-relocated at load; the table contents
 * are filled by the constructor below (runs before wpinstg's main). */
static int _tolow[384];
static int _toup[384];
const int *__ctype_tolower = _tolow + 128;
const int *__ctype_toupper = _toup + 128;

/* __ctype_b: libc5's char-classification table (384 entries, index -128..255),
 * a `const unsigned short *`. CRUCIAL: libc5 uses the SAME 16-bit bit layout as
 * glibc's _ISxxx -- that is exactly why glibc still ships a compatible compat
 * __ctype_b -- NOT the classic BSD `_ctype[]` 0x01..0x80 layout. Building it the
 * BSD way makes isdigit('0') false, so a display string like ":0" won't parse
 * and XOpenDisplay returns NULL. The correct 16-bit masks (verified against
 * glibc: '0'->0xd808, 'A'->0xd508, ' '->0x6001):
 *   _ISupper=0x0100 _ISlower=0x0200 _ISalpha=0x0400 _ISdigit=0x0800
 *   _ISxdigit=0x1000 _ISspace=0x2000 _ISprint=0x4000 _ISgraph=0x8000
 *   _ISblank=0x0001 _IScntrl=0x0002 _ISpunct=0x0004 _ISalnum=0x0008           */
static unsigned short _ctb[384];
const unsigned short *__ctype_b = _ctb + 128;

__attribute__((constructor))
static void init_ctype(void) {
    int i;
    for (i = -128; i < 0; i++) { _tolow[i + 128] = i; _toup[i + 128] = i; }
    for (i = 0; i < 256; i++) {
        _tolow[i + 128] = (i >= 'A' && i <= 'Z') ? i + 32 : i;
        _toup[i + 128] = (i >= 'a' && i <= 'z') ? i - 32 : i;
        int up = (i>='A'&&i<='Z'), lo = (i>='a'&&i<='z'), dig = (i>='0'&&i<='9');
        int hex = dig || (i>='a'&&i<='f') || (i>='A'&&i<='F');
        int sp = (i==' '||i=='\t'||i=='\n'||i=='\v'||i=='\f'||i=='\r');
        int blank = (i==' '||i=='\t');
        int cntrl = (i < 0x20 || i == 0x7f);
        int graph = (i >= 0x21 && i <= 0x7e);
        int print = (i >= 0x20 && i <= 0x7e);
        int alpha = up || lo, alnum = alpha || dig, punct = graph && !alnum;
        unsigned short v = 0;
        if (up)    v |= 0x0100;      /* _ISupper  */
        if (lo)    v |= 0x0200;      /* _ISlower  */
        if (alpha) v |= 0x0400;      /* _ISalpha  */
        if (dig)   v |= 0x0800;      /* _ISdigit  */
        if (hex)   v |= 0x1000;      /* _ISxdigit */
        if (sp)    v |= 0x2000;      /* _ISspace  */
        if (print) v |= 0x4000;      /* _ISprint  */
        if (graph) v |= 0x8000;      /* _ISgraph  */
        if (blank) v |= 0x0001;      /* _ISblank  */
        if (cntrl) v |= 0x0002;      /* _IScntrl  */
        if (punct) v |= 0x0004;      /* _ISpunct  */
        if (alnum) v |= 0x0008;      /* _ISalnum  */
        _ctb[i + 128] = v;
    }
    /* negative indices (-128..-1) stay 0 (static zero-init) */
}
