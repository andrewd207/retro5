/* r5core.h — retro5 core contracts shared by the feature modules.
 * SPDX-License-Identifier: MIT
 *
 * The binary-independent machinery every feature module builds on: the byte/GOT patch primitives,
 * the takeover-table appliers, symbol resolution, trampoline creation, and the global feature
 * flags/state. Defined once in r5core.c (in patch5.c until the extraction pass).
 *
 * INERT until the split: nothing #includes this yet, and the functions it declares are still
 * `static` in patch5.c. The extraction pass un-statics them, moves the bodies into r5core.c, and
 * points the module .c files here. Signatures mirror the current patch5.c definitions exactly so
 * that flip is a no-op for the compiler.
 */
#ifndef RETRO5_R5CORE_H
#define RETRO5_R5CORE_H
#include <stddef.h>
#include <stdint.h>
#include "r5syms.h"

/* ---- patch primitives (see patch5.c) ---- */
int  range_unmapped(const void *p, size_t n);                 /* 1 if any page in [p,p+n) is unmapped */
void patch_bytes(uintptr_t va, const void *guard, const void *repl, unsigned len);
void patch_call(uintptr_t va, const void *guard5, void *target);   /* rewrite a 5-byte call rel32 */
void patch_entry(uintptr_t va, const void *guard, unsigned glen, void *target);  /* `jmp ours` at entry */
int  patch_import(uintptr_t plt_va, uintptr_t got_va, void *target);             /* GOT-slot interpose */

/* ---- takeover-table appliers ---- */
void takeover_entries(const R5Entry *t, unsigned n);
void takeover_imports(const R5Import *t, unsigned n);
void takeover_methods(const R5Method *t, unsigned n);

/* ---- symbol resolution + trampolines ---- */
void *r5_realsym(const char *name);                           /* real libX11/libXt fn, never our stub */
void *r5_make_trampoline(uintptr_t va, unsigned keep);        /* copy `keep` bytes + jmp back; call orig */

/* ---- shared feature flags / state (RETRO5_* env, resolved in the constructor) ---- */
extern int r5_trace;                                          /* RETRO5_TRACE: log takeovers/draws */
extern int r5_cups;                                           /* RETRO5_CUPS: back printing with CUPS */

#endif /* RETRO5_R5CORE_H */
