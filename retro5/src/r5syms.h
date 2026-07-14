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
#include <X11/Intrinsic.h>   /* Widget / Window / Display / XtPointer — for the wheel-scroll Xt callback pointers below */

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
    uintptr_t fontcoll_build_va;  /* printer-font COLLECTION builder (detour: append system faces)  */
    /* ---- injected-font SELECTION survival (8.0; 0 on 8.1) --------------------------------------
     * WP collapses a picked face that is NOT a member of the active printer's font resource to the
     * printer default BEFORE storing it. Keeping the injected code (forcing the membership gate
     * 0x08417900) is not viable alone — WP then faults dereferencing the missing printer-font entry
     * (NULL name strlen, then a memcpy from the packed name block 0x08812f80 at an offset injected faces
     * lack); the real fix needs first-class printer-resource membership (§17.1). So we capture the pick
     * at fontset_va (the font-set command handler, which sees the chosen code pre-collapse) and render
     * that family via the resolver. font_state_ptr (+0x98 = active packed code) is kept for reference.
     * See FONT-RENDERING-MAP §17.2 + names.txt (Xvfb :160 RE). */
    uintptr_t fontset_va;         /* font-set command handler (op 0xbf), pre-collapse requested code */
    uintptr_t font_state_ptr;     /* -> current font-state object; +0x98 = active packed 12-bit font code */
    /* printer subsystem takeover (RETRO5_CUPS) — see FONT-RENDERING-MAP §15/§19. */
    uintptr_t printer_scan_va;    /* printer-list scan-core: int(void *ctx, int category) cdecl     */
    uintptr_t printer_rich_arr, printer_rich_cnt;  /* rich entry buffer calloc(cnt,0x9c) + count u16 */
    uintptr_t printer_flat_arr, printer_flat_cnt;  /* flat display-name char** + count u16 (dialog)  */
    uintptr_t cur_printer_name;   /* current-printer record name (+0x4c): the selected queue        */

    /* ---- mouse-wheel scroll (retroXt.c port; ONE shared wheel logic, per-build install) --------
     * The wheel logic (rx_wheel_target / rx_do_wheel in staged/takeover81.c) is binary-independent:
     * it drives scrollbars purely through the Xt callback pointers below, so the SAME code runs on
     * 8.0 (its takeover fills these with dlsym'd dynamic Xt) and 8.1 (fills them with xwp's STATIC
     * Xt addresses).  The three *_va fields are the static-detour targets: on 8.1 they are absolute
     * VAs into xwp's .text; on 8.0 they stay 0 (8.0 interposes the Xt symbols via the linker/GOT
     * instead of detouring, so no target address is needed). */
    uintptr_t xt_dispatch_va;      /* XtDispatchEvent entry (detour target)   — 8.1 0x08657ab0; 0 on 8.0 */
    uintptr_t xt_addgrab_va;       /* XtAddGrab entry       (detour target)   — 8.1 0x08657d00; 0 on 8.0 */
    uintptr_t xt_removegrab_va;    /* XtRemoveGrab entry    (detour target)   — 8.1 0x08657da0; 0 on 8.0 */
    uintptr_t xt_managechild_va;   /* XtManageChild entry   (detour target)   — 8.1 0x0865e040; 0 on 8.0 */
    uintptr_t xt_managechildren_va;/* XtManageChildren entry(detour target)   — 8.1 0x0865df30; 0 on 8.0 */
    /* Xt calls the shared wheel logic makes — resolved once per build (8.0: dlsym RTLD_NEXT; 8.1:
     * xwp's static addresses).  Typed so the shared logic calls them with no casts. */
    Widget (*XtWindowToWidget)(Display *, Window);
    Widget (*XtParent)(Widget);
    /* NOTE: the wheel READS scrollbar values through the non-varargs XtGetValues (the varargs
     * XtVaGetValues form is not symbolized in xwp's static 8.1 build).  Both builds fill this:
     * 8.1 = 0x08659f70; 8.0 = dlsym'd.  Callers marshal an Arg[] array (see takeover81.c). */
    void   (*XtGetValues)(Widget, ArgList, Cardinal);
    void   (*XtVaSetValues)(Widget, ...);
    int    (*XtHasCallbacks)(Widget, char * /*callback_name*/);  /* returns XtCallbackStatus */
    void   (*XtCallCallbacks)(Widget, char * /*callback_name*/, XtPointer);
    char  *(*XtName)(Widget);
    Window (*XtWindow)(Widget);
    /* 8.0 ONLY: WP's main loop is XtAppMainLoop, whose XtDispatchEvent call is libXt-internal and so
     * bypasses a GOT interpose.  8.0 therefore replaces XtAppMainLoop with a NextEvent+our-dispatch
     * loop (t81_XtAppMainLoop), for which it needs the real XtAppNextEvent.  0 on 8.1 (there the static
     * detour patches the XtDispatchEvent function itself, catching the XtAppMainLoop path too). */
    void   (*XtAppNextEvent)(XtAppContext, XEvent *);

    /* The REAL (unhooked) Xt entrypoints the shared wheel/menu handlers chain to.  BOTH builds fill
     * these: 8.1 = the detour trampolines saved by takeoverWP81_full; 8.0 = r5_realsym'd libXt fns
     * (8.0 GOT-interposes the shared handlers below, so it needs the originals to forward to). */
    Boolean (*real_dispatch)(XEvent *);
    void    (*real_addgrab)(Widget, Boolean, Boolean);
    void    (*real_removegrab)(Widget);
    void    (*real_managechild)(Widget);
    void    (*real_managechildren)(WidgetList, Cardinal);

    /* ---- §17.1 REAL FIX: base-space NAME->code resolver (8.0; 0 on 8.1) -------------------------
     * FUN_085b7a20 converts a stored font NAME to a 12-bit display code by bsearch()ing the display
     * record table (fontrec_arr / fontrec_snap) — which is sorted by name. retro5 appends injected
     * records unsorted at the end, so bsearch misses them and the name collapses to the printer
     * default; hooked to rescue injected names to their own display code (render + save/reload).
     * MUST STAY LAST (appending mid-struct shifts the Xt fn-ptr region and kills 8.0 startup). */
    uintptr_t name_to_code_va;    /* base-space name->code resolver entry (8.0 0x085b7a20)          */
} R5Syms;

extern R5Syms r5s;                /* the one instance (def in r5core.c / patch5.c pre-split) */

/* ---- shared mouse-wheel/menu handlers (takeover81.c) — ONE body for both builds ----
 * 8.1 installs these as inline detours over xwp's static Xt prologues (takeoverWP81_full);
 * 8.0 GOT-interposes the very same functions over its dynamic Xt imports.  Non-static so the
 * 8.0 install (patch5.c) can name them as patch_import targets. */
Boolean t81_XtDispatchEvent(XEvent *);
void    t81_XtAddGrab(Widget, Boolean, Boolean);
void    t81_XtRemoveGrab(Widget);
void    t81_XtManageChild(Widget);
void    t81_XtManageChildren(WidgetList, Cardinal);
void    t81_XtAppMainLoop(XtAppContext);  /* 8.0 main-loop replacement (NextEvent + our dispatch) */
void    takeoverWP81_full(void);          /* 8.1 static-detour install (applyWp8_1_Fixes) */
void    t81_wheel_config(void);           /* read RETRO5_WHEEL_LINES/RETROXT_WHEEL_LINES (both builds) */

/* ---- CUPS bridge: a printer record as printertocups' p2c_enum fills it (== P2CPrinter). ---- */
typedef struct { char name[128]; char info[128]; int is_default; } R5P2CPrinter;

#endif /* RETRO5_R5SYMS_H */
