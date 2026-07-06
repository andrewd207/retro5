/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* data5.c - libc5 DATA symbols that WP binaries copy-relocate (R_386_COPY)
 * and modern glibc no longer exports in a libc5-compatible form.
 *   _IO_stdin_      -> provided by glibc (not here)
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

/* __ctype_tolower / __ctype_toupper: pointers into 384-entry tables
 * (index range -128..255). glibc keeps the tables internal now, so we build
 * our own. The pointer values are copy-relocated at load; the table contents
 * are filled by the constructor below (runs before wpinstg's main). */
static int _tolow[384];
static int _toup[384];
const int *__ctype_tolower = _tolow + 128;
const int *__ctype_toupper = _toup + 128;

/* __ctype_b: libc5's char-classification table (384 entries, index -128..255),
 * a `const unsigned short *`. glibc no longer exports a libc5-LAYOUT table --
 * its compat __ctype_b uses glibc's _ISxxx bit layout, which is INCOMPATIBLE
 * with the libc5 macros -- so we build one with libc5's classic bit values:
 *   _U=0x01(upper) _L=0x02(lower) _N=0x04(digit) _S=0x08(space)
 *   _P=0x10(punct) _C=0x20(cntrl) _X=0x40(hex A-F/a-f) _B=0x80(blank ' ')
 * (Found missing by retro5/check-symbols.py on the 8.0.0076 build.) */
static unsigned short _ctb[384];
const unsigned short *__ctype_b = _ctb + 128;

__attribute__((constructor))
static void init_ctype(void) {
    int i;
    for (i = -128; i < 0; i++) { _tolow[i + 128] = i; _toup[i + 128] = i; }
    for (i = 0; i < 256; i++) {
        _tolow[i + 128] = (i >= 'A' && i <= 'Z') ? i + 32 : i;
        _toup[i + 128] = (i >= 'a' && i <= 'z') ? i - 32 : i;
        unsigned short v = 0;
        if (i >= 'A' && i <= 'Z') v |= 0x01;                 /* _U */
        if (i >= 'a' && i <= 'z') v |= 0x02;                 /* _L */
        if (i >= '0' && i <= '9') v |= 0x04;                 /* _N */
        if (i==' '||i=='\t'||i=='\n'||i=='\v'||i=='\f'||i=='\r') v |= 0x08; /* _S */
        if (i < 0x20 || i == 0x7f) v |= 0x20;                /* _C control */
        if ((i>='A'&&i<='F') || (i>='a'&&i<='f')) v |= 0x40; /* _X hex letters */
        if (i == ' ') v |= 0x80;                             /* _B blank */
        if (i >= 0x21 && i <= 0x7e &&                        /* _P punctuation */
            !((i>='A'&&i<='Z')||(i>='a'&&i<='z')||(i>='0'&&i<='9')))
            v |= 0x10;
        _ctb[i + 128] = v;
    }
    /* negative indices (-128..-1) stay 0 (static zero-init) */
}
