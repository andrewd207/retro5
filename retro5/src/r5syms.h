/* r5syms.h — shared data contracts for the retro5 feature modules.
 * SPDX-License-Identifier: MIT
 *
 * Part of the split of the monolithic patch5.c into feature-gated modules (r5skin / r5text /
 * r5docfont / r5fontinject / r5print / ...). This header holds the structures those modules share:
 * the per-build address/callback table (R5Syms), the three takeover-table shapes, and the CUPS
 * bridge's printer record. The single R5Syms instance `r5s` is defined once (in r5core.c after the
 * split; in patch5.c until then) and referenced everywhere via `extern`.
 *
 * NOTE: until the extraction pass removes the in-line definitions from patch5.c, nothing #includes
 * this header — it is inert and does not affect the build. Wiring it in (and un-static-ing r5s) is
 * the atomic step done when patch5.c is trimmed.
 */
#ifndef RETRO5_R5SYMS_H
#define RETRO5_R5SYMS_H
#include <stdint.h>

/* ---- the three reusable takeover-table shapes (see takeover_entries/imports/methods) ---- */
typedef struct {
    uintptr_t   va;           /* function entry to replace                                     */
    const char *guard;        /* bytes that must be there (the build fingerprint)              */
    unsigned    glen;
    void       *target;       /* our replacement                                               */
} R5Entry;

typedef struct {
    uintptr_t   plt;          /* the host's PLT stub for this import                           */
    uintptr_t   got;          /* its GOT slot (proved by the stub)                             */
    void       *target;       /* our replacement                                               */
    const char *name;         /* for RETRO5_DEBUG                                              */
} R5Import;

typedef struct {
    uintptr_t   class_rec;    /* widget class record                                           */
    uintptr_t   expect;       /* method fn currently in the slot                               */
    void       *target;       /* our replacement                                               */
    void      **saved;        /* where to stash the original                                   */
    const char *name;         /* for RETRO5_DEBUG                                              */
} R5Method;

/* ---- per-build address + callback table. One instance, filled by the matched build's apply(). ---- */
typedef struct {
    uintptr_t doc_text_va;        /* draw_text_run entry (8.0: entry-patch + trampoline)          */
    uintptr_t blit_site;          /* glyph-blit XCopyPlane call site (8.1 call-site patch); 0 on 8.0 */
    unsigned char blit_call[5];   /* guard bytes at blit_site (8.1)                                */
    uintptr_t xcp_plt, xcp_got;   /* XCopyPlane PLT/GOT for GOT interpose (8.0); 0 on 8.1          */
    uintptr_t xcp_fn;             /* real static XCopyPlane (8.1); 0 => resolve dynamically (8.0)  */
    uintptr_t pen_x, pen_y;       /* device pen X (glyph origin) / Y (baseline)                    */
    uintptr_t metric_ptr;         /* -> current metric struct; +0x00 = face-name char*            */
    uintptr_t font_ctx;           /* -> current font context; +0x04 hi16 = device px size          */
    uintptr_t fontrec_arr, fontrec_cnt;                  /* font-record ptr array + live count u16 */
    uintptr_t fontrec_snap;       /* base-count SNAPSHOT u16 — what the F9 list builder iterates    */
    unsigned (*glyphtab_get)(void);                      /* returns the current glyph table         */
    uintptr_t sel_filter_jne;     /* the "record+0x1e != 0" list filter jne to NOP (all-fonts)     */
    unsigned char sel_filter_bytes[2];                   /* guard: expected `75 XX`                 */
    /* system-font injection: grow the record table + remap and append records */
    uintptr_t fontrec_cap;        /* record-array capacity u16                                     */
    uintptr_t remap_arr, remap_cap;  /* remap[0xfff-code]->index ptr + capacity u16               */
    uintptr_t freecode;           /* next-free 12-bit fontcode counter u16 (inits 0xfff, counts down) */
    uintptr_t builder_va;         /* font-table builder entry (detour: run original, then inject)  */
    uintptr_t resolver_va;        /* font resolver (code->record); hooked to track injected face   */
    /* printer subsystem takeover (RETRO5_CUPS) — see FONT-RENDERING-MAP §15/§19. */
    uintptr_t printer_scan_va;    /* printer-list scan-core: int(void *ctx, int category) cdecl     */
    uintptr_t printer_rich_arr, printer_rich_cnt;  /* rich entry buffer calloc(cnt,0x9c) + count u16 */
    uintptr_t printer_flat_arr, printer_flat_cnt;  /* flat display-name char** + count u16 (dialog)  */
    uintptr_t cur_printer_name;   /* current-printer record name (+0x4c): the selected queue        */
} R5Syms;

extern R5Syms r5s;                /* the one instance (def in r5core.c / patch5.c pre-split) */

/* ---- CUPS bridge: a printer record as printertocups' p2c_enum fills it (== P2CPrinter). ---- */
typedef struct { char name[128]; char info[128]; int is_default; } R5P2CPrinter;

#endif /* RETRO5_R5SYMS_H */
