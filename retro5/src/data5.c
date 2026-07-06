/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* data5.c - libc5 DATA symbols that wpinstg copy-relocates (R_386_COPY)
 * and modern glibc no longer exports.
 *   __ctype_b, _IO_stdin_  -> still provided by glibc (not here)
 *   widget classes         -> provided by modern libXt (not here)
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

__attribute__((constructor))
static void init_ctype(void) {
    int i;
    for (i = -128; i < 0; i++) { _tolow[i + 128] = i; _toup[i + 128] = i; }
    for (i = 0; i < 256; i++) {
        _tolow[i + 128] = (i >= 'A' && i <= 'Z') ? i + 32 : i;
        _toup[i + 128] = (i >= 'a' && i <= 'z') ? i - 32 : i;
    }
}
