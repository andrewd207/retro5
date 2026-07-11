/* detour81.h -- minimal x86-32 inline-detour engine for WP 8.1's statically
 * linked Xt/X11 functions.  WP 8.1's `xwp` is a non-PIC ELF EXEC, so the target
 * function addresses are ABSOLUTE and fixed (see wp81_detours.h); we rewrite each
 * prologue in-memory to `jmp hook` and build a trampoline that runs the relocated
 * prologue then jumps back, so a hook can still call the original.
 *
 * Load path: LD_PRELOAD (or a DT_NEEDED rewrite) gets this .so mapped and its
 * constructor run; the static callers reach the patched code via their direct
 * `call`s -- no symbol interposition needed (and none is possible on 8.1).
 */
#ifndef DETOUR81_H
#define DETOUR81_H

typedef struct {
    const char   *name;    /* for logging only */
    void         *target;  /* absolute addr of the function in xwp .text */
    void         *hook;    /* replacement; must match the target's ABI/signature */
    void        **orig;    /* OUT: set to a trampoline that calls the original */
    unsigned char steal;   /* prologue bytes to relocate (>=5, from wp81_detours.h) */
} detour_t;

/* Install n detours. Returns the number successfully installed.
 * Call once, before the target code runs (i.e. from a library constructor). */
int detour_install(detour_t *tab, int n);

/* Optional printf-style log sink (default NULL = silent). The engine avoids
 * libc stdio on purpose (retro5 exports a libc5 FILE layout that corrupts glibc
 * FILE* output); a sink here lets the caller route messages via its own safe
 * writer (e.g. retroXt's vsnprintf+raw-write logger). */
extern void (*detour_log)(const char *fmt, ...);

#endif /* DETOUR81_H */
