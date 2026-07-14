/* patch5.c — retro5 RUNTIME in-memory fixups for known WordPerfect 8 executables.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * DESIGN: the ONLY on-disk change to a WP binary is the DT_NEEDED retarget (libc.so.5 & friends
 * -> retro5.so, done by the installer as same-length byte edits). Every FUNCTIONAL fix is applied
 * here, in memory, when retro5.so is loaded:
 *
 *     findBinaryFixes()   (constructor, runs before the host's main)
 *        -> matchBinaryHash()          identify the host by a hash of a fixed .text window
 *        -> applyWp8_0_dynX_Fixes()    run THAT binary's own self-contained fix routine
 *
 * Each known executable gets its OWN `applyXxxFixes()` — concentrated, obvious, self-documenting,
 * rather than one anonymous list. Two layers of safety: the hash gates which binary we touch, and
 * each fixup independently byte-guards its exact site before writing. An unrecognised binary (or
 * any other process that loads retro5, e.g. wpexc) hashes to nothing and is left untouched. xwp is
 * non-PIE (fixed base 0x08048000) so absolute VAs are stable; every site is mincore-probed first,
 * so touching a binary whose text differs (wpexc) never faults.
 *
 * Set RETRO5_DEBUG=1 to print which binary matched. Add a build: hash its .text window, add one
 * KNOWN_BINARIES row + one applyXxxFixes(). See wp8-modern/docs/wild-source-pointer-crashes.md.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* ======================================================================================= *
 *  Generic primitives (build-independent)
 * ======================================================================================= */

/* is any page of [p, p+n) unmapped? (cheap, fault-free — safe on any host binary) */
int range_unmapped(const void *p, size_t n) {   /* non-static: shared with takeover81.c (r5core.h) */
    if (!n) return 0;
    long pg = sysconf(_SC_PAGESIZE); if (pg <= 0) pg = 4096;
    uintptr_t a = (uintptr_t)p, start = a & ~(uintptr_t)(pg - 1);
    uintptr_t npages = ((a + n - start) + (pg - 1)) / pg;
    unsigned char vec[256];
    if (npages > sizeof vec) npages = sizeof vec;
    return syscall(SYS_mincore, (void *)start, (size_t)(npages * pg), vec) != 0;
}

/* FNV-1a/32 over a memory range (used to identify the host binary) */
static uint32_t fnv1a(const void *p, size_t n) {
    const uint8_t *b = p; uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

/* write into a read-only code page, then restore R-X protection */
static void write_code(uintptr_t va, const uint8_t *bytes, unsigned len) {
    long pg = sysconf(_SC_PAGESIZE); if (pg <= 0) pg = 4096;
    uintptr_t lo = va & ~(uintptr_t)(pg - 1);
    uintptr_t hi = (va + len + pg - 1) & ~(uintptr_t)(pg - 1);
    if (mprotect((void *)lo, hi - lo, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return;
    memcpy((void *)va, bytes, len);
    mprotect((void *)lo, hi - lo, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)va, (char *)(va + len));
}

/* byte-guarded raw replace: only touch a site whose current bytes match `guard` (len bytes) */
static void patch_bytes(uintptr_t va, const void *guard, const void *repl, unsigned len) {
    if (range_unmapped((void *)va, len)) return;
    if (memcmp((void *)va, guard, len) != 0) return;      /* already patched / wrong build */
    write_code(va, repl, len);
}
/* byte-guarded call redirect: rewrite a 5-byte `call rel32` at `va` to call retro5 `target` */
static void patch_call(uintptr_t va, const void *guard5, void *target) {
    if (range_unmapped((void *)va, 5)) return;
    if (memcmp((void *)va, guard5, 5) != 0) return;
    uint8_t buf[5]; int32_t rel = (int32_t)((uintptr_t)target - (va + 5));
    buf[0] = 0xe8; memcpy(buf + 1, &rel, 4);
    write_code(va, buf, 5);
}

/* byte-guarded full replace: overwrite a function's ENTRY with `jmp target`, so every one of its
 * hundreds of call sites lands in ours instead. The jmp pushes nothing, so the caller's cdecl frame
 * arrives intact and `target`'s own `ret` returns to the real caller — the original body never runs.
 * Verified safe for the Motif draw primitives: all are cdecl (plain `ret`, caller cleans), so even a
 * mis-declared arg count cannot imbalance the stack. `guard`/`glen` may cover more than the 5 bytes
 * we overwrite (we match the sub-esp imm too), which pins the exact build. */
void patch_entry(uintptr_t va, const void *guard, unsigned glen, void *target) {   /* non-static: takeover81.c */
    if (range_unmapped((void *)va, glen)) return;
    if (memcmp((void *)va, guard, glen) != 0) return;     /* wrong build / already patched */
    uint8_t buf[6];
    int32_t rel = (int32_t)((uintptr_t)target - (va + 5));
    buf[0] = 0xe9;                                        /* jmp rel32 */
    memcpy(buf + 1, &rel, 4);
    if (glen > 5) buf[5] = 0x90;                          /* nop-pad the guarded 6th byte */
    write_code(va, buf, glen > 5 ? 6 : 5);
}

/* Byte-guarded METHOD swap: overwrite a function pointer inside a widget's class record and hand
 * back the original. This is the preferred takeover when the thing we want is an Xt/Motif class
 * method (expose, resize, ...), because there is no code to patch at all — the class record is
 * plain data, the swap is a single word, and `*saved` gives us a clean, prologue-intact way to
 * still run the original. `expect` pins the exact build: if the slot does not already hold the
 * function we mapped, we leave it alone.
 *
 * Xt CoreClassPart is a fixed layout, so a method's slot is (class_record + offset); expose lives
 * at +68 on 32-bit. See R5_EXPOSE_OFF. */
static int patch_method(uintptr_t class_rec, unsigned off, uintptr_t expect,
                        void *target, void **saved) {
    void **slot = (void **)(class_rec + off);
    long pg;
    uintptr_t lo;
    if (range_unmapped(slot, 4)) return 0;
    if ((uintptr_t)*slot != expect) return 0;             /* wrong build / already patched */

    /* An Xt class record lives in writable .data by definition — Xt itself writes to it during
     * class initialisation (class_inited, resource merging) — so R/W is the page's NORMAL state and
     * there is nothing to hand back afterwards. The mprotect is only insurance for a host that
     * managed to land the record in RELRO; if even that fails we decline the swap rather than
     * fault. (Contrast write_code(), which really is touching R-X text and must restore it.) */
    pg = sysconf(_SC_PAGESIZE); if (pg <= 0) pg = 4096;
    lo = (uintptr_t)slot & ~(uintptr_t)(pg - 1);
    if (mprotect((void *)lo, (size_t)pg, PROT_READ | PROT_WRITE) != 0) return 0;
    if (saved) *saved = *slot;
    *slot = target;
    return 1;
}
#define R5_EXPOSE_OFF 68          /* offsetof(CoreClassPart, expose) on 32-bit Xt */

/* Guarded IMPORT swap: redirect one of the host's calls into a shared library (XLoadQueryFont, ...)
 * by rewriting its GOT slot. No code is patched at all — we just change where the PLT stub jumps.
 *
 * We cannot interpose these by exporting the symbol: retro5.so is LAST in the host's DT_NEEDED
 * list, so libX11's definition always wins the lookup. The GOT is the only place the choice is
 * actually made, and it is one word.
 *
 * The guard is the PLT stub itself: `ff 25 <got>` proves both that we have the right build AND
 * that `got` really is this symbol's slot — the two facts that matter, checked against each other.
 * Lazy binding means the slot may still point back into the PLT when we run (we are a constructor,
 * before main); that is fine, we are replacing it wholesale and nothing re-resolves it later. */
static int patch_import(uintptr_t plt_va, uintptr_t got_va, void *target) {
    uint8_t guard[6];
    if (range_unmapped((void *)plt_va, 6) || range_unmapped((void *)got_va, 4)) return 0;
    guard[0] = 0xff; guard[1] = 0x25;                     /* jmp *disp32 */
    memcpy(guard + 2, &got_va, 4);
    if (memcmp((void *)plt_va, guard, 6) != 0) return 0;  /* wrong build / not this symbol's stub */
    *(void **)got_va = target;                            /* .got.plt is writable by definition */
    return 1;
}

/* ======================================================================================= *
 *  Fix helpers referenced by the per-binary routines
 * ======================================================================================= */

/* Guarded copy — fix for the table-QuickFill code-stream parser crash.
 * The parser can run its read pointer a 64 KB page past its 256-byte buffer (a DOS-heritage
 * 16-bit bounds check misses it) and copy from an unmapped source. Interposed at the parser's
 * copy call: unmapped source -> skip (graceful degrade); else memmove (build-independent, exact
 * overlap semantics). cdecl (dst, src, n), returns dst. */
void *retro5_guarded_copy(void *dst, const void *src, unsigned n) {
    if (range_unmapped(src, n)) return dst;
    return memmove(dst, src, n);
}

/* Guarded strcpy — proper fix for the morpher as-you-type OOB strcpy.
 * mor_read_entry indexes a 43-entry particle table with an unguarded `byte & 0x7f`; for idx>0x2a
 * it fetches 4 bytes past the table and hands them to strcpy AS THE SOURCE POINTER (the caught
 * crash had src="dddd" = keystrokes). Rather than NOP the call (which drops even valid copies),
 * we interpose: a wild (unmapped) source is skipped; a valid one is copied exactly as before.
 * cdecl (dst, src), returns dst. */
char *retro5_guarded_strcpy(char *dst, const char *src) {
    if (range_unmapped(src, 1)) return dst;               /* OOB index -> wild src -> skip */
    return strcpy(dst, src);
}

/* Guarded XtVaGetValues — fix for the PerfectExpert (and any null-widget) crash.
 * WP's PerfectExpert hide/cleanup handler saves the panel's position with
 * XtVaGetValues(widget, XtNx,&x, XtNy,&y, NULL) BEFORE its null-check — but on the toggle-on
 * path the widget global is still NULL (panel not yet created), so it crashes in
 * XtWidgetToApplicationContext. Interposed at that call site: a NULL/unmapped widget returns
 * harmlessly (position left untouched), letting the handler fall through to its null-check and
 * the command proceed to actually create+show the panel. For a valid widget we rebuild the
 * ArgList from the varargs (GetValues form = (name, addr) pairs, NULL-terminated) and forward to
 * the real XtGetValues (resolved lazily via dlsym) -- so behaviour is unchanged when it matters.
 * cdecl (widget, ...). */
typedef struct { char *name; long value; } R5Arg;
static void (*g_XtGetValues)(void *, R5Arg *, unsigned);
void retro5_guarded_XtVaGetValues(void *w, ...) {
    if (!w || range_unmapped(w, 4)) return;               /* NULL/invalid widget -> skip, no crash */
    if (!g_XtGetValues) g_XtGetValues = (void (*)(void *, R5Arg *, unsigned))
                                        dlsym(RTLD_DEFAULT, "XtGetValues");
    if (!g_XtGetValues) return;                            /* can't forward -> skip (safe) */
    R5Arg args[64]; unsigned n = 0; char *name;
    va_list ap; va_start(ap, w);
    while ((name = va_arg(ap, char *)) != 0 && n < 64) {
        args[n].name = name;
        args[n].value = (long)va_arg(ap, void *);         /* GetValues: value is the out-address */
        n++;
    }
    va_end(ap);
    g_XtGetValues(w, args, n);
}

/* ======================================================================================= *
 *  Motif draw-primitive takeover — the modern chrome
 * ======================================================================================= *
 * Motif is statically linked into xwp, so there is no Xm symbol to interpose. But every widget
 * paints its bevels/arrows/rules by calling the SAME handful of internal draw primitives, so
 * replacing those four entries restyles the entire app at once — and we land inside the draw call
 * with full geometry + semantics already in the args, so there is nothing to classify.
 *
 * What changes: the chunky 3D bevel (the dated signature) becomes a 1px rounded outline; arrows
 * become thin chevrons; separators become a hairline; the focus ring picks up the accent color.
 *
 * Safety: a wrong draw is a cosmetic glitch, never a segfault — a strictly safer class of change
 * than the crash fixes above. Every X function is resolved lazily via dlsym from the already-loaded
 * libX11 (xwp NEEDs it), so retro5 gains no link dependency and still loads into non-X hosts
 * (wpinstg, wpexc). RETRO5_SKIN=0 disables the takeover, for a one-env-var A/B against stock Motif.
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>   /* Region (the third arg of every Xt expose method) */
#include <X11/Intrinsic.h>   /* Widget / ArgList / Cardinal / WidgetList — for the shared R5Syms table */

/* Shared data contracts (R5Entry/R5Import/R5Method/R5Syms/R5P2CPrinter + the wheel handler protos).
 * takeover81.c includes the same header, so both TUs agree on r5s's layout byte-for-byte and the
 * one `r5s` instance (defined non-static below) is safe to share.  This replaces the formerly inline
 * copies of these typedefs further down in this file. */
#include "r5syms.h"

/* shadow_type (arg 10 of _XmDrawShadows). These are Motif's real XmShadowType values, confirmed by
 * tracing the live binary — the toolbar sends 8 at rest and 7 when latched. (Beware: they are NOT
 * 1..4; that mapping is a common mis-transcription, and using it silently disables every
 * pressed-state check, because nothing ever equals 3.) */
#define R5_ETCHED_IN  5
#define R5_ETCHED_OUT 6
#define R5_SHADOW_IN  7
#define R5_SHADOW_OUT 8
/* direction (arg 11 of _XmDrawArrow) */
#define R5_ARROW_UP    0
#define R5_ARROW_DOWN  1
#define R5_ARROW_LEFT  2
#define R5_ARROW_RIGHT 3

/* The palette. Deliberately cool + low-contrast: against retroXt's #E8E8E8 face these read as a
 * modern light theme, and against stock Motif gray they still look clean. The one exception is the
 * SUNKEN pair, which is deliberately high-contrast — see r5_inset() for why. */
#define R5_COL_EDGE     0xb6bac0u   /* raised outline — buttons, frames, scrollbar at rest */
#define R5_COL_SUNK     0x515a68u   /* SUNKEN outline — pressed/latched. Dark on purpose.   */
#define R5_COL_SUNK_IN  0x9aa4b2u   /* sunken inner top/left line — sells the recess        */
#define R5_COL_HAIRLINE 0xa6abb3u   /* etched rules, separators, group boxes. Must stay clearly
                                     * darker than the ~#d3d3d3 chrome background or dividers vanish
                                     * (the toolbar group separators did — #d2d6db was ~invisible). */
#define R5_COL_GLYPH    0x5a6270u   /* arrow chevrons — soft slate, never black             */
#define R5_COL_PRESS    0xccd4e0u   /* pressed/latched button FACE — only ownable from expose */
#define R5_COL_ACCENT   0x3a7bd5u   /* selected/checked indicator fill — the one saturated color */
#define R5_COL_WHITE    0xffffffu   /* unchecked indicator interior + the checkmark            */

/* 0xRRGGBB -> cairo's 0..1 doubles */
#define R5_RD(c) (((double)(((c) >> 16) & 0xff)) / 255.0)
#define R5_GD(c) (((double)(((c) >>  8) & 0xff)) / 255.0)
#define R5_BD(c) (((double)( (c)        & 0xff)) / 255.0)

enum { R5_GC_EDGE, R5_GC_SUNK, R5_GC_SUNK_IN, R5_GC_HAIRLINE, R5_GC_GLYPH, R5_GC_PRESS, R5_GC_N };
static const uint32_t R5_RGB[R5_GC_N] = {
    R5_COL_EDGE, R5_COL_SUNK, R5_COL_SUNK_IN, R5_COL_HAIRLINE, R5_COL_GLYPH, R5_COL_PRESS
};

static int r5_skin = 1;             /* RETRO5_SKIN=0 -> leave Motif's drawing alone (all appearance off) */
static int r5_text = 1;             /* cairo text layer: RETRO5_TEXT=
                                     *   1 / unset -> full (load cairo, warm fontconfig, hook draw+metrics)
                                     *   0         -> off (no cairo load, no warm, no hooks)
                                     *   "load"    -> DIAGNOSTIC: dlopen cairo's lib graph ONLY — run its
                                     *                constructors, but no fontconfig init and no hooks.
                                     *   "warm"    -> DIAGNOSTIC: load + FcInit (font scan), still NO hooks.
                                     *                load vs warm vs full isolates libs / fontconfig / hooks. */
int r5_trace;                       /* RETRO5_TRACE=1 -> log every draw call + its widget (shared, r5core.h) */
static int r5_wheel = 1;            /* RETRO5_WHEEL=0 -> disable mouse-wheel scrolling (default ON) */

/* True once the text layer is fully wired at library init (cairo loaded, all reals resolved, hooks
 * installed). Set before WP runs, so every hooked call from WP finds a pure, linker-free hook. */
static int r5_text_active;

/* ---- the X/Xt call layer, bound two different ways ----
 * The painters below are binary-independent, but HOW they reach X is not. A dynamically-linked host
 * (8.0: libX11/libXt are DT_NEEDED) resolves the entry points by NAME. The near-static WP builds
 * link Xlib straight into the executable, where there is no dynamic symbol to look up — so those
 * binaries hand us a table of absolute VAs instead, and everything above this line stays identical.
 * That is the whole reason this is a vtable and not a pile of direct calls. */
typedef struct {
    uintptr_t CreateGC, SetLineAttributes, SetDashes, DrawSegments, DrawPoints, DrawLines,
              DrawRectangle, FillRectangle, AllocColor, GetGCValues, QueryColor, GetGeometry,
              CopyArea, CopyPlane, CreatePixmap, FreePixmap, GetImage, PutImage,
              XtDisplayOfObject, XtWindowOfObject;
} R5XSyms;

static struct {
    int      ready;                 /* 0 = untried, 1 = usable, -1 = unavailable */
    GC     (*CreateGC)(Display *, Drawable, unsigned long, XGCValues *);
    int    (*SetLineAttributes)(Display *, GC, unsigned, int, int, int);
    int    (*SetDashes)(Display *, GC, int, const char *, int);
    int    (*DrawSegments)(Display *, Drawable, GC, XSegment *, int);
    int    (*DrawPoints)(Display *, Drawable, GC, XPoint *, int, int);
    int    (*DrawLines)(Display *, Drawable, GC, XPoint *, int, int);
    int    (*DrawRectangle)(Display *, Drawable, GC, int, int, unsigned, unsigned);
    int    (*FillRectangle)(Display *, Drawable, GC, int, int, unsigned, unsigned);
    Status (*AllocColor)(Display *, Colormap, XColor *);
    Status (*GetGCValues)(Display *, GC, unsigned long, XGCValues *);
    int    (*QueryColor)(Display *, Colormap, XColor *);
    Status (*GetGeometry)(Display *, Drawable, Window *, int *, int *,
                          unsigned *, unsigned *, unsigned *, unsigned *);
    int    (*CopyArea)(Display *, Drawable, Drawable, GC, int, int,
                       unsigned, unsigned, int, int);
    int    (*CopyPlane)(Display *, Drawable, Drawable, GC, int, int,
                        unsigned, unsigned, int, int, unsigned long);
    Pixmap (*CreatePixmap)(Display *, Drawable, unsigned, unsigned, unsigned);
    int    (*FreePixmap)(Display *, Pixmap);
    XImage *(*GetImage)(Display *, Drawable, int, int, unsigned, unsigned, unsigned long, int);
    int    (*PutImage)(Display *, Drawable, GC, XImage *, int, int, int, int, unsigned, unsigned);
    Display *(*XtDisplayOfObject)(void *);
    Window   (*XtWindowOfObject)(void *);
} r5x;

/* Set by the per-binary takeover when the host is static; NULL means "resolve by name". */
static const R5XSyms *r5_xsyms;

/* Resolve from libX11/libXt directly, NEVER dlsym(RTLD_DEFAULT). In this ancient host RTLD_DEFAULT
 * mis-resolves Xt symbols — e.g. it returned XtDisplayOfObject's address for "XtWindowOfObject", so
 * we read a Display* as a window and XGetGeometry'd garbage. Defined below; forward-declared here. */
static void *r5_realsym(const char *name);

/* member <- the genuine library symbol   (dynamic hosts)
 * member <- absolute VA from the binary's own table   (static hosts) */
#define R5_SYM(memb, sym) (*(void **)&r5x.memb = r5_realsym(sym), r5x.memb != 0)
#define R5_ADDR(memb)     (r5_xsyms->memb && !range_unmapped((void *)r5_xsyms->memb, 1) \
                           ? (*(void **)&r5x.memb = (void *)r5_xsyms->memb, 1) : 0)

static int r5_xlib(void) {
    if (r5x.ready) return r5x.ready > 0;
    r5x.ready = -1;                                       /* try once; never retry on failure */
    if (r5_xsyms) {                                       /* static host: absolute addresses */
        if (R5_ADDR(CreateGC) && R5_ADDR(SetLineAttributes) && R5_ADDR(SetDashes) &&
            R5_ADDR(DrawSegments) &&
            R5_ADDR(DrawPoints) && R5_ADDR(DrawLines) && R5_ADDR(DrawRectangle) &&
            R5_ADDR(FillRectangle) &&
            R5_ADDR(AllocColor) && R5_ADDR(GetGCValues) && R5_ADDR(QueryColor) &&
            R5_ADDR(GetGeometry) && R5_ADDR(CopyArea) && R5_ADDR(CopyPlane) &&
            R5_ADDR(CreatePixmap) && R5_ADDR(FreePixmap) &&
            R5_ADDR(GetImage) && R5_ADDR(PutImage) &&
            R5_ADDR(XtDisplayOfObject) && R5_ADDR(XtWindowOfObject))
            r5x.ready = 1;
    } else {                                              /* dynamic host: resolve by name */
        if (R5_SYM(CreateGC,          "XCreateGC")          &&
            R5_SYM(SetLineAttributes, "XSetLineAttributes") &&
            R5_SYM(SetDashes,         "XSetDashes")         &&
            R5_SYM(DrawSegments,      "XDrawSegments")      &&
            R5_SYM(DrawPoints,        "XDrawPoints")        &&
            R5_SYM(DrawLines,         "XDrawLines")         &&
            R5_SYM(DrawRectangle,     "XDrawRectangle")     &&
            R5_SYM(FillRectangle,     "XFillRectangle")     &&
            R5_SYM(AllocColor,        "XAllocColor")        &&
            R5_SYM(GetGCValues,       "XGetGCValues")       &&
            R5_SYM(QueryColor,        "XQueryColor")        &&
            R5_SYM(GetGeometry,       "XGetGeometry")       &&
            R5_SYM(CopyArea,          "XCopyArea")          &&
            R5_SYM(CopyPlane,         "XCopyPlane")         &&
            R5_SYM(CreatePixmap,      "XCreatePixmap")      &&
            R5_SYM(FreePixmap,        "XFreePixmap")        &&
            R5_SYM(GetImage,          "XGetImage")          &&
            R5_SYM(PutImage,          "XPutImage")          &&
            R5_SYM(XtDisplayOfObject, "XtDisplayOfObject")  &&
            R5_SYM(XtWindowOfObject,  "XtWindowOfObject"))
            r5x.ready = 1;
    }
    return r5x.ready > 0;
}

/* Luminance (0-255) of an X pixel value. XQueryColor round-trips, so memoize — the whole UI uses a
 * handful of shadow pixels, and this sits in the repaint hot path. */
static struct { unsigned long pix; int lum; } r5_lum_cache[16];
static int r5_lum_n;
static int r5_lum(Display *dpy, unsigned long pix) {
    XColor c;
    int i, l;
    for (i = 0; i < r5_lum_n; i++)
        if (r5_lum_cache[i].pix == pix) return r5_lum_cache[i].lum;
    c.pixel = pix;
    if (!r5x.QueryColor(dpy, DefaultColormap(dpy, DefaultScreen(dpy)), &c)) return -1;
    l = (int)(((c.red >> 8) * 30 + (c.green >> 8) * 59 + (c.blue >> 8) * 11) / 100);
    if (r5_lum_n < 16) { r5_lum_cache[r5_lum_n].pix = pix; r5_lum_cache[r5_lum_n].lum = l; r5_lum_n++; }
    return l;
}

/* ---- who is asking? recovering the Widget from the caller's frame ----
 * The draw primitives take no widget, but their CALLER is the widget's Redisplay/expose method,
 * whose signature is Redisplay(Widget w, XEvent*, Region) — so the widget is sitting in the
 * caller's first argument slot. We arrive by `jmp`, so no frame was pushed on our behalf: our own
 * saved-ebp IS the caller's ebp, and its arg1 is at caller_ebp+8.
 *
 * This is a stack walk into someone else's frame, so it is validated, not trusted. An Xt Widget's
 * first field is `self`, a pointer BACK TO ITSELF — a signature no random stack value fakes. We
 * mincore-probe every hop and bail to NULL on anything unexpected; the worst case is that we lose
 * the class name and fall back to the GC-tone heuristic, never a fault.
 *
 * Xt layout (32-bit): Widget{ 0:self, 4:widget_class, 8:parent } ; WidgetClass{ 0:superclass,
 * 4:class_name } */
static void *r5_caller_widget(void) {
    void **ebp, **cebp, *w;
    ebp = (void **)__builtin_frame_address(0);
    if (!ebp || range_unmapped(ebp, 8)) return 0;
    cebp = (void **)ebp[0];                               /* caller's frame pointer */
    if (!cebp || range_unmapped(cebp, 16)) return 0;
    w = cebp[2];                                          /* caller_ebp+8 = its first argument */
    if (!w || range_unmapped(w, 12)) return 0;
    if (*(void **)w != w) return 0;                       /* not an Xt Widget (no self-pointer) */
    return w;
}

/* Class name of a widget recovered above, or NULL. Validated to be a plausible C string. */
const char *r5_widget_class(void *w) {   /* non-static: shared with takeover81.c */
    void *cls;
    const char *name;
    int i;
    if (!w) return 0;
    cls = *(void **)((char *)w + 4);                      /* core.widget_class */
    if (!cls || range_unmapped(cls, 8)) return 0;
    name = *(const char **)((char *)cls + 4);             /* core_class.class_name */
    if (!name || range_unmapped(name, 2)) return 0;
    for (i = 0; i < 40; i++) {                            /* printable, NUL-terminated, non-empty */
        char c = name[i];
        if (c == 0) return i ? name : 0;
        if (c < 0x20 || c > 0x7e) return 0;
    }
    return 0;
}

/* Which way is the light coming from? Motif encodes "pressed" two different ways depending on the
 * widget: some pass shadow_type=XmSHADOW_IN, others keep XmSHADOW_OUT and simply SWAP the top and
 * bottom shadow GCs (WP's toolbar toggles do exactly this). Comparing the two GCs' tones catches
 * both: if the TOP edge is darker than the BOTTOM edge, the widget is lit from below — sunken.
 * Returns 1 sunken, 0 raised, -1 unknown. */
static int r5_sunken(Display *dpy, GC top_gc, GC bottom_gc, unsigned type) {
    XGCValues tv, bv;
    int lt, lb;
    if (type == R5_SHADOW_IN) return 1;                   /* said so outright */
    if (!top_gc || !bottom_gc) return -1;
    if (!r5x.GetGCValues(dpy, top_gc, GCForeground, &tv)) return -1;
    if (!r5x.GetGCValues(dpy, bottom_gc, GCForeground, &bv)) return -1;
    if (tv.foreground == bv.foreground) return -1;        /* flat: no bevel intended */
    lt = r5_lum(dpy, tv.foreground);
    lb = r5_lum(dpy, bv.foreground);
    if (lt < 0 || lb < 0) return -1;
    return lt < lb;                                       /* dark on top = lit from below = sunken */
}

/* One GC per palette color, made once against the first drawable we see and reused forever — so a
 * repaint costs no XSetForeground round-trip. (xwp is single-screen/single-depth; a drawable of a
 * different depth would fail XCreateGC, and we simply skip drawing rather than risk an X error.) */
static Display *r5_gc_dpy;
static GC       r5_gc[R5_GC_N];

static GC r5_pick(Display *dpy, Drawable d, int idx) {
    if (!r5_xlib()) return 0;
    if (r5_gc_dpy != dpy) {                               /* (re)build the cache for this Display */
        memset(r5_gc, 0, sizeof r5_gc);
        r5_gc_dpy = dpy;
    }
    if (!r5_gc[idx]) {
        XGCValues v;
        XColor c;
        Colormap cm = DefaultColormap(dpy, DefaultScreen(dpy));
        uint32_t rgb = R5_RGB[idx];
        c.red   = (unsigned short)(((rgb >> 16) & 0xff) * 257);
        c.green = (unsigned short)(((rgb >>  8) & 0xff) * 257);
        c.blue  = (unsigned short)(( rgb        & 0xff) * 257);
        c.flags = DoRed | DoGreen | DoBlue;
        if (!r5x.AllocColor(dpy, cm, &c)) return 0;       /* colormap full -> draw nothing */
        v.foreground = c.pixel;
        v.line_width = 1;
        v.cap_style  = CapRound;
        v.join_style = JoinRound;
        r5_gc[idx] = r5x.CreateGC(dpy, d, GCForeground | GCLineWidth | GCCapStyle | GCJoinStyle, &v);
    }
    return r5_gc[idx];
}

/* A 1px rounded rectangle: four sides pulled in by the corner radius, plus the four corner pixels.
 * Two X requests, and it is the whole reason the result reads as modern rather than merely flat —
 * square 1px corners still look like a 1990s dialog. */
static void r5_round_rect(Display *dpy, Drawable d, GC gc, int x, int y, int w, int h) {
    XSegment s[4];
    XPoint   p[4];
    int x1 = x + w - 1, y1 = y + h - 1;
    if (w < 4 || h < 4) {                                 /* too small to round — plain box */
        s[0].x1 = x;  s[0].y1 = y;  s[0].x2 = x1; s[0].y2 = y;
        s[1].x1 = x;  s[1].y1 = y1; s[1].x2 = x1; s[1].y2 = y1;
        s[2].x1 = x;  s[2].y1 = y;  s[2].x2 = x;  s[2].y2 = y1;
        s[3].x1 = x1; s[3].y1 = y;  s[3].x2 = x1; s[3].y2 = y1;
        r5x.DrawSegments(dpy, d, gc, s, 4);
        return;
    }
    s[0].x1 = x + 2;  s[0].y1 = y;       s[0].x2 = x1 - 2; s[0].y2 = y;        /* top    */
    s[1].x1 = x + 2;  s[1].y1 = y1;      s[1].x2 = x1 - 2; s[1].y2 = y1;       /* bottom */
    s[2].x1 = x;      s[2].y1 = y + 2;   s[2].x2 = x;      s[2].y2 = y1 - 2;   /* left   */
    s[3].x1 = x1;     s[3].y1 = y + 2;   s[3].x2 = x1;     s[3].y2 = y1 - 2;   /* right  */
    r5x.DrawSegments(dpy, d, gc, s, 4);
    p[0].x = x + 1;  p[0].y = y + 1;
    p[1].x = x1 - 1; p[1].y = y + 1;
    p[2].x = x + 1;  p[2].y = y1 - 1;
    p[3].x = x1 - 1; p[3].y = y1 - 1;
    r5x.DrawPoints(dpy, d, gc, p, 4, CoordModeOrigin);
}

/* The sunken treatment: a dark outline plus a soft inner line down the top and left edges — the
 * light-from-above cue that says "recessed" without a 3D bevel.
 *
 * Why not just fill the face with a pressed tint (the obvious modern answer)? Because we cannot:
 * Motif draws a widget's icon/label BEFORE it calls _XmDrawShadows, so anything we fill inside this
 * rect paints straight over the content. (Verified: a probe fill erased every toolbar icon.) What
 * IS safe is the 1-2px gutter Motif already reserved for the bevel it asked us to draw — no icon
 * ever extends into it. So the recess is sold with edges alone, and the contrast between
 * R5_COL_EDGE (rest) and R5_COL_SUNK (pressed) is cranked deliberately wide to make latched
 * toolbar toggles unmistakable at a glance. A true filled/rounded pressed face needs the button's
 * expose method, not this primitive. */
static void r5_inset(Display *dpy, Drawable d, int x, int y, int w, int h) {
    GC edge = r5_pick(dpy, d, R5_GC_SUNK);
    GC in   = r5_pick(dpy, d, R5_GC_SUNK_IN);
    XSegment s[2];
    if (!edge) return;
    r5_round_rect(dpy, d, edge, x, y, w, h);
    if (!in || w < 6 || h < 6) return;
    s[0].x1 = x + 2; s[0].y1 = y + 1; s[0].x2 = x + w - 3; s[0].y2 = y + 1;   /* inner top  */
    s[1].x1 = x + 1; s[1].y1 = y + 2; s[1].x2 = x + 1;     s[1].y2 = y + h - 3; /* inner left */
    r5x.DrawSegments(dpy, d, in, s, 2);
}

/* _XmDrawShadows — every 3D bevel in the app: buttons, frames, menus, scrollbar trough, toolbars.
 * Highest-leverage hook by far. The bevel becomes one rounded 1px outline, and `type` — the
 * sunken/raised/etched flag Motif already computed — is all the semantics we need: no widget
 * lookup, no classification. cdecl (dpy, d, top_gc, bottom_gc, x, y, w, h, thickness, type)
 * — 10 args, confirmed against the live binary by disassembly. */
void retro5_XmDrawShadows(Display *dpy, Drawable d, GC top_gc, GC bottom_gc,
                          int x, int y, int w, int h, int thickness, unsigned type) {
    GC gc;
    int sunk;
    const char *cls;
    void *cw;
    if (thickness <= 0 || w <= 0 || h <= 0) return;       /* Motif asks for nothing -> draw nothing */
    if (!dpy || !d) return;
    if (!r5_xlib()) return;

    sunk = r5_sunken(dpy, top_gc, bottom_gc, type);
    cw   = r5_caller_widget();                            /* who is being painted? */
    cls  = r5_widget_class(cw);
    if (r5_trace) {
        char b[220];
        void *ccls = cw ? *(void **)((char *)cw + 4) : 0;
        void *exp  = (ccls && !range_unmapped((char *)ccls + R5_EXPOSE_OFF, 4))
                     ? *(void **)((char *)ccls + R5_EXPOSE_OFF) : 0;
        int n = snprintf(b, sizeof b,
                         "shadow %-22s w=%3d h=%3d thick=%d type=%u sunk=%2d class=%p expose=%p\n",
                         cls ? cls : "(unknown)", w, h, thickness, type, sunk, ccls, exp);
        if (n > 0) write(2, b, (size_t)n);
    }

    (void)cw;
    if (sunk == 1) {                                      /* pressed / latched / recessed */
        r5_inset(dpy, d, x, y, w, h);
        return;
    }

    /* A toolbar button at rest wears no frame at all. WP's toolbar buttons are XmDrawnButton (its
     * dialog buttons are XmPushButton), and we know which we are painting because the caller's
     * frame hands us the widget. Stock Motif boxed every icon in a raised bevel; dropping the box
     * until the button is actually pressed is what makes the toolbar read as modern — and it means
     * the pressed state is the ONLY box on the bar, so a latched tool is unmissable. */
    if (cls && !strcmp(cls, "XmDrawnButton")) return;

    gc = r5_pick(dpy, d, (type == R5_ETCHED_IN || type == R5_ETCHED_OUT)
                         ? R5_GC_HAIRLINE                 /* group boxes, rules */
                         : R5_GC_EDGE);                   /* raised: buttons, frames */
    if (gc) r5_round_rect(dpy, d, gc, x, y, w, h);
}

/* _XmDrawArrow — scrollbar end buttons, cascade chevrons, spinners. Motif's is a filled 3D
 * triangle; ours is a thin two-stroke chevron, centered in the box Motif allocated.
 * cdecl (dpy, d, top_gc, bottom_gc, center_gc, x, y, w, h, thickness, direction) — 11 args. */
void retro5_XmDrawArrow(Display *dpy, Drawable d, GC top_gc, GC bottom_gc, GC center_gc,
                        int x, int y, int w, int h, int thickness, unsigned char direction) {
    XPoint v[3];
    GC gc;
    int cx, cy, a;
    (void)top_gc; (void)bottom_gc; (void)center_gc; (void)thickness;
    if (w <= 0 || h <= 0 || !dpy || !d) return;
    if (!(gc = r5_pick(dpy, d, R5_GC_GLYPH))) return;

    cx = x + w / 2; cy = y + h / 2;
    a  = (w < h ? w : h) / 4;                             /* chevron half-span: scales with the box */
    if (a < 2) a = 2;

    switch (direction) {
        case R5_ARROW_UP:    v[0].x = cx - a; v[0].y = cy + a / 2;
                             v[1].x = cx;     v[1].y = cy - a / 2;
                             v[2].x = cx + a; v[2].y = cy + a / 2; break;
        case R5_ARROW_DOWN:  v[0].x = cx - a; v[0].y = cy - a / 2;
                             v[1].x = cx;     v[1].y = cy + a / 2;
                             v[2].x = cx + a; v[2].y = cy - a / 2; break;
        case R5_ARROW_LEFT:  v[0].x = cx + a / 2; v[0].y = cy - a;
                             v[1].x = cx - a / 2; v[1].y = cy;
                             v[2].x = cx + a / 2; v[2].y = cy + a; break;
        default:             v[0].x = cx - a / 2; v[0].y = cy - a;
                             v[1].x = cx + a / 2; v[1].y = cy;
                             v[2].x = cx - a / 2; v[2].y = cy + a; break;
    }
    r5x.SetLineAttributes(dpy, gc, 2, LineSolid, CapRound, JoinRound);
    r5x.DrawLines(dpy, d, gc, v, 3, CoordModeOrigin);
    r5x.SetLineAttributes(dpy, gc, 1, LineSolid, CapRound, JoinRound);   /* leave it as we found it */
}

/* _XmDrawSeparator — the etched double-rule between menu groups, toolbar groups and dialog sections
 * becomes a single hairline, inset from the ends so it reads as a divider rather than a border.
 * cdecl (dpy, d, top_gc, bottom_gc, sep_gc, x, y, w, h, thickness, margin, orientation, type).
 *
 * We derive the line direction from the GEOMETRY, not the `orientation` arg — the arg's constant
 * encoding is not reliable across builds (drawing toolbar group separators horizontal instead of
 * vertical), whereas the shape is unambiguous: a separator is a thin rectangle, so the long side is
 * the line. Tall+narrow (h > w) is a vertical divider; wide+short is a horizontal rule. */
void retro5_XmDrawSeparator(Display *dpy, Drawable d, GC top_gc, GC bottom_gc, GC sep_gc,
                            int x, int y, int w, int h, int thickness, int margin,
                            unsigned char orientation, unsigned char type) {
    XSegment s;
    GC gc;
    (void)top_gc; (void)bottom_gc; (void)sep_gc; (void)thickness; (void)orientation; (void)type;
    if (w <= 0 || h <= 0 || !dpy || !d) return;
    if (!(gc = r5_pick(dpy, d, R5_GC_HAIRLINE))) return;

    if (h > w) {                                          /* tall & narrow -> vertical divider */
        int cx = x + w / 2;
        s.x1 = cx; s.y1 = y + margin; s.x2 = cx; s.y2 = y + h - 1 - margin;
    } else {                                              /* wide & short -> horizontal rule */
        int cy = y + h / 2;
        s.x1 = x + margin; s.y1 = cy; s.x2 = x + w - 1 - margin; s.y2 = cy;
    }
    r5x.DrawSegments(dpy, d, gc, &s, 1);
}

/* _XmDrawHighlight — the focus indicator. Motif draws a heavy solid box (highlightThickness deep,
 * usually black) around the widget; we draw the modern equivalent — a thin DOTTED rectangle inset
 * just inside the widget edge. Motif calls this on every focus change (BorderHighlight /
 * BorderUnhighlight), passing the highlight GC to DRAW and the widget-background GC to ERASE, so by
 * drawing with hl_gc we inherit that pairing exactly: focus-on paints the dotted ring in the
 * highlight color, focus-off repaints the identical path in the background (erasing it). We
 * temporarily set dashes on hl_gc and restore solid afterward. cdecl (dpy, d, gc, x, y, w, h,
 * thickness, line_style) — 9 args. */
void retro5_XmDrawHighlight(Display *dpy, Drawable d, GC hl_gc,
                            int x, int y, int w, int h, int thickness, int line_style) {
    static const char dots[2] = { 1, 2 };                 /* 1 on, 2 off -> fine dotted */
    int inset = thickness > 1 ? thickness : 2;
    int rx, ry, rw, rh;
    (void)line_style;
    if (thickness <= 0 || w <= 0 || h <= 0) return;       /* nothing asked for -> nothing drawn */
    if (!dpy || !d || !hl_gc) return;
    if (!r5_xlib()) return;

    rx = x + inset; ry = y + inset;
    rw = w - 1 - 2 * inset; rh = h - 1 - 2 * inset;
    if (rw < 3 || rh < 3) { rx = x; ry = y; rw = w - 1; rh = h - 1; }  /* too small -> full edge */

    r5x.SetLineAttributes(dpy, hl_gc, 1, LineOnOffDash, CapButt, JoinMiter);
    r5x.SetDashes(dpy, hl_gc, 0, dots, 2);
    r5x.DrawRectangle(dpy, d, hl_gc, rx, ry, (unsigned)rw, (unsigned)rh);
    r5x.SetLineAttributes(dpy, hl_gc, 1, LineSolid, CapButt, JoinMiter);  /* leave it as Motif expects */
}

/* ======================================================================================= *
 *  Cairo text layer — WP's X text rendered with the system font engine
 * ======================================================================================= *
 * WP is pure X-core-font: it asks for fonts by XLFD, DRAWS with XDrawString / XDrawImageString, and
 * MEASURES with XTextWidth / XTextExtents. A modern X server has no FreeType core-font backend, so
 * core fonts cannot reach the system's TrueType/OpenType faces at all — the only way to a modern
 * font is to stop drawing through X and draw with cairo (which resolves families through
 * fontconfig). So we take over the draw AND the measure calls together and satisfy both from one
 * cairo font: WP lays its controls out to widths we return, and we draw to exactly those widths, so
 * layout and rendering can never disagree.
 *
 * Unlike retroXt (which had to composite an image surface over a live Motif widget and so could
 * only touch opaque XDrawImageString), we ARE XDrawString now — we render glyphs straight onto the
 * same Drawable at the same baseline, so plain strings composite over their background with nothing
 * to fight. The one hard constraint we keep from retroXt is real: cairo is dlopen'd RTLD_DEEPBIND,
 * or its (and fontconfig's) libc calls bind to retro5's libc5 shims and font init deadlocks.
 *
 * Safety: any font/string/drawable we cannot handle falls back to the real X call, so the worst
 * case is legacy-looking text, never missing text. RETRO5_SKIN=0 disables the whole layer. */
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>

/* --- alias table: WP XLFD family -> cairo family (which fontconfig resolves to a real font) --- */
#define R5_FONT_RULES 32
static struct { char pat[64], repl[64]; } r5_fonts[R5_FONT_RULES];
static int r5_font_n, r5_font_loaded;

static int r5_glob(const char *pat, const char *s) {   /* one-wildcard glob, case-insensitive */
    for (; *pat; pat++, s++) {
        if (*pat == '*') {
            if (!pat[1]) return 1;
            for (; *s; s++) if (r5_glob(pat + 1, s)) return 1;
            return r5_glob(pat + 1, s);
        }
        if (!*s) return 0;
        if (*pat != *s && !(*pat >= 'A' && *pat <= 'Z' && *pat + 32 == *s)
                       && !(*s   >= 'A' && *s   <= 'Z' && *s   + 32 == *pat)) return 0;
    }
    return !*s;
}
static void r5_font_add(const char *pat, const char *repl) {
    if (r5_font_n >= R5_FONT_RULES) return;
    strncpy(r5_fonts[r5_font_n].pat,  pat,  sizeof r5_fonts[0].pat  - 1);
    strncpy(r5_fonts[r5_font_n].repl, repl, sizeof r5_fonts[0].repl - 1);
    r5_font_n++;
}
/* ~/.config/retro5/fonts.conf ($RETRO5_FONTS): `wp-family-glob   cairo-family`, # comments.
 *     -*-helvetica-*     Inter
 * The config is where per-skin taste lives; it is read before the built-ins, so it wins. */
static void r5_font_config(void) {
    char path[512], line[256];
    const char *env = getenv("RETRO5_FONTS"), *home = getenv("HOME");
    FILE *f;
    if (env && *env) { strncpy(path, env, sizeof path - 1); path[sizeof path - 1] = 0; }
    else if (home)   { snprintf(path, sizeof path, "%s/.config/retro5/fonts.conf", home); }
    else return;
    if (!(f = fopen(path, "r"))) return;
    while (fgets(line, sizeof line, f)) {
        char *p = line, *pat, *repl, *e;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || !*p) continue;
        pat = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        *p++ = 0;
        while (*p == ' ' || *p == '\t') p++;
        repl = p;
        for (e = repl + strlen(repl); e > repl && (e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '); ) *--e = 0;
        if (*repl) r5_font_add(pat, repl);
    }
    fclose(f);
}
/* Built-ins map WP's stock faces onto cairo generic families. "Sans"/"Serif"/"Monospace" are
 * fontconfig aliases, so they resolve to whatever modern face the system actually installed —
 * which is exactly the "integrate the system font engine" we want, with no hard-coded face. */
static void r5_font_init(void) {
    if (r5_font_loaded) return;
    r5_font_loaded = 1;
    r5_font_config();
    r5_font_add("*helvetica*", "Sans");
    r5_font_add("*courier*",   "Monospace");
    r5_font_add("*times*",     "Serif");
}
/* Ask the desktop what UI font it actually uses, so WP inherits the user's real font instead of a
 * generic. GNOME/most environments answer `gsettings get org.gnome.desktop.interface <key>` with
 * e.g. 'Cantarell 11'; failing that, GTK's settings.ini carries `gtk-font-name`. We keep only the
 * family (WP's XLFD still decides the size). Cached; a miss just leaves the generic default. */
static char r5_desk_prop[64], r5_desk_mono[64];
static int  r5_desk_done;

static void r5_strip_size_quotes(char *s) {             /* 'Cantarell Bold 11' -> Cantarell Bold */
    char *e;
    if (*s == '\'' || *s == '"') { memmove(s, s + 1, strlen(s)); }
    for (e = s + strlen(s); e > s && (e[-1]=='\n'||e[-1]=='\r'||e[-1]=='\''||e[-1]=='"'||e[-1]==' '); )
        *--e = 0;
    e = s + strlen(s);                                  /* drop a trailing point size */
    while (e > s && e[-1] >= '0' && e[-1] <= '9') e--;
    while (e > s && e[-1] == ' ') e--;
    *e = 0;
}
/* File-only, NEVER fork. WP does a timing-sensitive pipe handshake with helper processes at
 * startup, and a popen() here would fork WP — duplicating those pipe fds into a shell child and
 * desyncing the handshake (the "spawned-process/IPC" hang). So we read config files directly:
 * GTK's settings.ini carries `gtk-font-name = Family Size`, which tracks the GNOME/desktop UI font
 * on every mainstream environment. `key` selects the line (gtk-font-name / gtk-monospace...). */
static int r5_gtk_font_file(const char *rel, const char *key, char *out, int outsz) {
    char path[512], line[256]; const char *home = getenv("HOME"); FILE *f; int ok = 0;
    if (!home) return 0;
    snprintf(path, sizeof path, "%s/%s", home, rel);
    if (!(f = fopen(path, "r"))) return 0;
    while (fgets(line, sizeof line, f)) {
        char *v = strstr(line, key);
        if (v && (v = strchr(v, '=')) != 0) {
            v++; while (*v == ' ') v++;
            strncpy(out, v, outsz - 1); out[outsz - 1] = 0;
            r5_strip_size_quotes(out); ok = out[0] != 0; break;
        }
    }
    fclose(f);
    return ok;
}
static void r5_desktop_init(void) {
    if (r5_desk_done) return;
    r5_desk_done = 1;
    r5_gtk_font_file(".config/gtk-3.0/settings.ini", "gtk-font-name", r5_desk_prop, sizeof r5_desk_prop)
      || r5_gtk_font_file(".config/gtk-4.0/settings.ini", "gtk-font-name", r5_desk_prop, sizeof r5_desk_prop)
      || r5_gtk_font_file(".gtkrc-2.0", "gtk-font-name", r5_desk_prop, sizeof r5_desk_prop);
    if (r5_trace) {
        char b[160]; int k = snprintf(b, sizeof b, "retro5: desktop UI font prop='%s'\n",
                     r5_desk_prop); if (k > 0) write(2, b, (size_t)k);
    }
}

static const char *r5_family_for(const char *xlfd_family, int mono) {
    int i;
    if (xlfd_family && *xlfd_family) {
        r5_font_init();
        for (i = 0; i < r5_font_n; i++)                  /* explicit rules win */
            if (r5_glob(r5_fonts[i].pat, xlfd_family)) return r5_fonts[i].repl;
    }
    r5_desktop_init();                                   /* else the desktop's own UI font */
    if (mono && r5_desk_mono[0]) return r5_desk_mono;
    if (!mono && r5_desk_prop[0]) return r5_desk_prop;
    return mono ? "Monospace" : "Sans";                  /* last resort: fontconfig generic */
}

/* --- cairo, dlopen'd RTLD_DEEPBIND (see banner) --- */
static struct {
    int ready;
    cairo_surface_t *(*xlib_surface_create)(Display *, Drawable, Visual *, int, int);
    cairo_surface_t *(*image_surface_create)(cairo_format_t, int, int);
    cairo_t *(*create)(cairo_surface_t *);
    void (*destroy)(cairo_t *);
    void (*surface_destroy)(cairo_surface_t *);
    void (*surface_flush)(cairo_surface_t *);
    void (*set_source_rgb)(cairo_t *, double, double, double);
    void (*move_to)(cairo_t *, double, double);
    void (*line_to)(cairo_t *, double, double);
    void (*rectangle)(cairo_t *, double, double, double, double);
    void (*arc)(cairo_t *, double, double, double, double, double);
    void (*new_sub_path)(cairo_t *);
    void (*close_path)(cairo_t *);
    void (*fill)(cairo_t *);
    void (*stroke)(cairo_t *);
    void (*set_line_width)(cairo_t *, double);
    void (*set_line_cap)(cairo_t *, cairo_line_cap_t);
    void (*set_line_join)(cairo_t *, cairo_line_join_t);
    void (*select_font_face)(cairo_t *, const char *, cairo_font_slant_t, cairo_font_weight_t);
    void (*set_font_size)(cairo_t *, double);
    void (*show_text)(cairo_t *, const char *);
    void (*text_extents)(cairo_t *, const char *, cairo_text_extents_t *);
    cairo_status_t (*status)(cairo_t *);
    /* icon rendering (optional — bound separately so a miss cannot fail the text layer) */
    int icons_ok;
    void (*paint)(cairo_t *);
    void (*set_source_surface)(cairo_t *, cairo_surface_t *, double, double);
    void (*scale)(cairo_t *, double, double);
    void (*translate)(cairo_t *, double, double);
    void (*save)(cairo_t *);
    void (*restore)(cairo_t *);
    cairo_surface_t *(*png_create)(const char *);
    int (*img_w)(cairo_surface_t *);
    int (*img_h)(cairo_surface_t *);
    cairo_status_t (*surface_status)(cairo_surface_t *);
} cz;

/* Non-blocking check used by the draw/measure hot path: is cairo ready to use? We NEVER dlopen from
 * here — the load is done once at library init (r5_cairo_preload), before WP's main and before any
 * helper is spawned, because a heavy dlopen inside a startup expose stalls WP's main thread while it
 * is mid-IPC-handshake and the app hangs. Until preload has finished, text falls back to real X. */
static int r5_cairo(void) { return cz.ready > 0; }

/* STEP 1 — just load the library graph (cairo + its deps: fontconfig, freetype, pixman, xcb, ...)
 * and bind the symbols. This runs every dependency's ELF CONSTRUCTOR. It does NOT init fontconfig
 * (no font scan) and does NOT touch X. Split out from the warm/hook steps so a diagnostic build can
 * do exactly this and nothing else — to answer "is merely loading these libs what breaks WP?" */
static int r5_cairo_load(void) {
    void *h;
    if (cz.ready) return cz.ready > 0;
    cz.ready = -1;
    if (!(h = dlopen("libcairo.so.2", RTLD_NOW | RTLD_DEEPBIND))) return 0;
#define CZ(m, s) (*(void **)&cz.m = dlsym(h, s), cz.m != 0)
    if (!(CZ(xlib_surface_create, "cairo_xlib_surface_create") &&
          CZ(image_surface_create, "cairo_image_surface_create") &&
          CZ(create, "cairo_create") && CZ(destroy, "cairo_destroy") &&
          CZ(surface_destroy, "cairo_surface_destroy") && CZ(surface_flush, "cairo_surface_flush") &&
          CZ(set_source_rgb, "cairo_set_source_rgb") && CZ(move_to, "cairo_move_to") &&
          CZ(line_to, "cairo_line_to") && CZ(rectangle, "cairo_rectangle") &&
          CZ(arc, "cairo_arc") && CZ(new_sub_path, "cairo_new_sub_path") &&
          CZ(close_path, "cairo_close_path") && CZ(fill, "cairo_fill") &&
          CZ(stroke, "cairo_stroke") && CZ(set_line_width, "cairo_set_line_width") &&
          CZ(set_line_cap, "cairo_set_line_cap") && CZ(set_line_join, "cairo_set_line_join") &&
          CZ(select_font_face, "cairo_select_font_face") && CZ(set_font_size, "cairo_set_font_size") &&
          CZ(show_text, "cairo_show_text") && CZ(text_extents, "cairo_text_extents") &&
          CZ(status, "cairo_status")))
        return 0;
#undef CZ
    /* Icon-render symbols: OPTIONAL. Bound after cz.ready so a missing one (e.g. cairo built
     * without PNG) only disables icon replacement, never the text layer. */
#define CZ2(m, s) (*(void **)&cz.m = dlsym(h, s))
    CZ2(paint, "cairo_paint");                 CZ2(set_source_surface, "cairo_set_source_surface");
    CZ2(scale, "cairo_scale");                 CZ2(translate, "cairo_translate");
    CZ2(save, "cairo_save");                   CZ2(restore, "cairo_restore");
    CZ2(png_create, "cairo_image_surface_create_from_png");
    CZ2(img_w, "cairo_image_surface_get_width");  CZ2(img_h, "cairo_image_surface_get_height");
    CZ2(surface_status, "cairo_surface_status");
#undef CZ2
    cz.icons_ok = (cz.paint && cz.set_source_surface && cz.scale && cz.translate && cz.save &&
                   cz.restore && cz.png_create && cz.img_w && cz.img_h && cz.surface_status);
    cz.ready = 1;
    return 1;
}

/* --- librsvg, dlopen'd at init (see the preload call), never inside an expose. Only loaded when
 * RETRO5_ICONS is set. We build handles from an IN-MEMORY buffer (rsvg_handle_new_from_data), NOT
 * from a path: rsvg_handle_new_from_file goes through GFile -> g_vfs_get_default -> a GIO module
 * directory scan that stalls at 100% CPU (observed hanging WP inside a startup expose). The memory
 * API uses a GMemoryInputStream and never touches the VFS. render_document scales the SVG into a
 * viewport; g_object_unref frees the handle (a GObject, from libgobject pulled in by librsvg). --- */
static struct {
    int   ready;
    void *(*new_from_data)(const unsigned char *data, size_t len, void **err);
    int   (*render_document)(void *handle, cairo_t *cr, const void *viewport, void **err);
    void  (*g_unref)(void *);
} rvz;

static int r5_rsvg(void) { return rvz.ready > 0; }

static int r5_rsvg_load(void) {
    void *h, *g;
    if (rvz.ready) return rvz.ready > 0;
    rvz.ready = -1;
    if (!(h = dlopen("librsvg-2.so.2", RTLD_NOW | RTLD_DEEPBIND))) return 0;
    if (!(g = dlopen("libgobject-2.0.so.0", RTLD_NOW | RTLD_DEEPBIND | RTLD_NOLOAD)) &&
        !(g = dlopen("libgobject-2.0.so.0", RTLD_NOW | RTLD_DEEPBIND))) return 0;
    *(void **)&rvz.new_from_data   = dlsym(h, "rsvg_handle_new_from_data");
    *(void **)&rvz.render_document = dlsym(h, "rsvg_handle_render_document");
    *(void **)&rvz.g_unref         = dlsym(g, "g_object_unref");
    if (!rvz.new_from_data || !rvz.render_document || !rvz.g_unref) return 0;
    rvz.ready = 1;
    /* Warm the gtype/parser machinery once, here at init (off any expose), with a trivial doc. */
    {
        static const char tiny[] = "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>";
        void *err = 0, *hd = rvz.new_from_data((const unsigned char *)tiny, sizeof tiny - 1, &err);
        if (hd) rvz.g_unref(hd);
    }
    return 1;
}

/* Read a whole file into a malloc'd buffer (caller frees). Returns NULL on any error. */
static unsigned char *r5_read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long n;
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || n > (16 << 20)) { fclose(f); return 0; }
    rewind(f);
    if (!(buf = (unsigned char *)malloc((size_t)n + 1))) { fclose(f); return 0; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return 0; }
    fclose(f);
    buf[n] = 0;
    *out_len = (size_t)n;
    return buf;
}

/* STEP 2 — force FcInit + first face load (the font-info part), on an image surface so no X is
 * needed. Process-global-cached, so the first real draw is cheap. Separate from load() so it can
 * be skipped by the diagnostic build. */
static void r5_cairo_warm(void) {
    cairo_surface_t *ms;
    cairo_t *cr;
    cairo_text_extents_t te;
    if (cz.ready <= 0) return;
    if ((ms = cz.image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1)) != 0) {
        if ((cr = cz.create(ms)) != 0) {
            cz.select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cz.set_font_size(cr, 13.0);
            cz.text_extents(cr, "Ag", &te);
            cz.destroy(cr);
        }
        cz.surface_destroy(ms);
    }
}

/* --- per-font record, keyed by the X Font XID: the lifecycle hook the design turns on ---
 * WP allocates fonts (XLoadQueryFont) and frees them (XFreeFont), and every draw/measure GC carries
 * the Font XID of the font in play. That XID is our key: we build a record the first time we see a
 * font, keep it alongside WP's, and drop it when WP frees the font. The record holds everything the
 * cairo path needs (family + size + style), computed ONCE, so per-glyph work is just rendering. */
#define R5_XA_FONT ((Atom)18)              /* predefined XA_FONT property = the font's XLFD */
#define R5_UNSPECIFIED_PIXMAP ((Pixmap)2)  /* Motif's XmUNSPECIFIED_PIXMAP — "this label has no pixmap" */
typedef struct {
    Font id;
    int  used;
    int  passthrough;                      /* symbol/dingbat/pi font: leave to X, wrong glyphs else */
    double size;                           /* cairo em size, from the X pixel height */
    const char *family;
    cairo_font_slant_t  slant;
    cairo_font_weight_t weight;
} R5Font;
static R5Font r5_ftab[32];

/* Resolve a symbol from libX11/libXt DIRECTLY, never via RTLD_DEFAULT. This is essential for any
 * symbol whose GOT slot we have taken over: dlsym(RTLD_DEFAULT, "XLoadQueryFont") in this host does
 * NOT return libX11's function — it returns the executable's own PLT stub, which we redirected to
 * our hook, so calling it re-enters us forever (proven: 174k-deep recursion -> stack overflow).
 * dlopen(RTLD_NOLOAD) hands back the library that is already mapped, and dlsym on THAT handle
 * returns the genuine implementation. */
static void *r5_realsym(const char *name) {
    static void *h11, *hxt;
    void *p = 0;
    if (!h11) h11 = dlopen("libX11.so.6", RTLD_NOLOAD | RTLD_NOW);
    if (!hxt) hxt = dlopen("libXt.so.6",  RTLD_NOLOAD | RTLD_NOW);
    if (h11) p = dlsym(h11, name);
    if (!p && hxt) p = dlsym(hxt, name);
    if (!p) p = dlsym(RTLD_DEFAULT, name);               /* last resort */
    return p;
}

/* Real X calls we still need. r5_XQueryFont is one we TOOK OVER, so it must come from libX11
 * directly (r5_realsym), or we would recurse into our own retro5_XQueryFont. */
static XFontStruct *(*r5_XQueryFont)(Display *, XID);
static Status (*r5_XGetGCValues)(Display *, GC, unsigned long, XGCValues *);
static char *(*r5_XGetAtomName)(Display *, Atom);
static int   (*r5_XFreeFontInfo)(char **, XFontStruct *, int);
static void  r5_bind_helpers(void) {
    if (r5_XQueryFont) return;
    *(void **)&r5_XQueryFont    = r5_realsym("XQueryFont");
    *(void **)&r5_XGetGCValues  = r5_realsym("XGetGCValues");
    *(void **)&r5_XGetAtomName  = r5_realsym("XGetAtomName");
    *(void **)&r5_XFreeFontInfo = r5_realsym("XFreeFontInfo");
}

/* Pull the XLFD family + charset out of a loaded font, so we can alias the family and spot the
 * symbol fonts we must NOT re-render. XLFD: -fndry-FAMILY-wght-slant-...-spacing-...-CHARSET */
static void r5_parse_xlfd(const char *xlfd, char *family, int fsz,
                          int *bold, int *italic, int *symbolic) {
    const char *f[14];
    int n = 0, i;
    const char *p = xlfd;
    family[0] = 0; *bold = *italic = *symbolic = 0;
    if (!xlfd || xlfd[0] != '-') return;
    for (p = xlfd; *p && n < 14; p++) if (*p == '-') f[n++] = p + 1;
    if (n < 3) return;
    for (i = 0; f[1][i] && f[1][i] != '-' && i < fsz - 1; i++) family[i] = f[1][i];
    family[i] = 0;
    if (n > 2 && (!strncmp(f[2], "bold", 4) || !strncmp(f[2], "Bold", 4))) *bold = 1;
    if (n > 3 && (f[3][0] == 'i' || f[3][0] == 'o' || f[3][0] == 'I' || f[3][0] == 'O')) *italic = 1;
    /* charset is the tail after the last two hyphens; symbol/pi fonts carry these markers */
    if (strstr(xlfd, "fontspecific") || strstr(xlfd, "ymbol") || strstr(xlfd, "dingbat") ||
        strstr(xlfd, "ruler") || strstr(xlfd, "wpicon")) *symbolic = 1;
}

/* ---- the DPI-aware UI scale ----
 * WP was built for late-'90s displays (~75-96 dpi), where its fixed-pixel fonts looked comfortably
 * large; on a modern high-dpi panel the same pixel counts render tiny. r5_scale() is the factor we
 * grow the UI by: render size AND the metrics WP measures (so controls reserve the extra room), kept
 * in lock-step so text still fits its widget. Default is derived from the screen's real dpi against an
 * 84 baseline — so an ordinary ~96 dpi screen already gets a modest ~1.14x bump (WP's fixed-pixel
 * fonts read a touch small even at 96 dpi), and genuinely high-dpi panels scale further.
 * RETRO5_UI_SCALE overrides it outright. Floored at 1.0 — we never render SMALLER than stock — and
 * capped so a mis-reported dpi can't blow the UI up. Computed once, when a Display first exists (it
 * does by font-load time). */
#define R5_DPI_BASE 84.0                                /* dpi mapping to 1.0; 96 dpi -> ~1.14 */
static double r5_ui_scale_env;                          /* RETRO5_UI_SCALE, 0 = unset */
static double r5_ui_scale_cache;                        /* 0 = not yet computed */
static Display *r5_dpy;                                 /* stashed Display for the no-Display metrics */
static double r5_scale(void) {
    double s = 96.0 / R5_DPI_BASE;                       /* default assumes an ordinary ~96 dpi screen */
    if (r5_ui_scale_cache > 0) return r5_ui_scale_cache;
    if (r5_ui_scale_env > 0) {
        s = r5_ui_scale_env;
    } else if (r5_dpy) {
        int scr = DefaultScreen(r5_dpy);
        int mm  = DisplayHeightMM(r5_dpy, scr);
        int px  = DisplayHeight(r5_dpy, scr);
        if (mm > 0 && px > 0) s = (px * 25.4 / mm) / R5_DPI_BASE;   /* real dpi when known */
    }
    if (s < 1.0)  s = 1.0;                               /* never below stock */
    if (s > 1.75) s = 1.75;                              /* guard a bogus dpi */
    if (r5_ui_scale_env > 0 || r5_dpy) r5_ui_scale_cache = s;   /* cache once we had a basis */
    return s;
}

/* Build (or fetch cached) our cairo record for an already-loaded font, keyed by fs->fid. The
 * XLFD is taken from `xlfd_hint` (the name WP passed to XLoadQueryFont) when known, else from the
 * font's own XA_FONT property. Does NOT free fs — the caller owns it. */
static R5Font *r5_font_intern(Display *dpy, XFontStruct *fs, const char *xlfd_hint) {
    R5Font *slot = 0;
    char family[64], *xlfd = 0;
    int i, p, bold = 0, italic = 0, sym = 0, mono;
    Atom nameatom = 0;
    Font fid;

    if (!fs) return 0;
    fid = fs->fid;
    for (i = 0; i < 32; i++) {
        if (r5_ftab[i].used && r5_ftab[i].id == fid) return &r5_ftab[i];
        if (!slot && !r5_ftab[i].used) slot = &r5_ftab[i];
    }
    if (!slot) return 0;

    mono = (fs->max_bounds.width > 0 && fs->min_bounds.width == fs->max_bounds.width);
    if (xlfd_hint && xlfd_hint[0] == '-') {
        r5_parse_xlfd(xlfd_hint, family, (int)sizeof family, &bold, &italic, &sym);
        if (r5_trace) { char b[220]; int k = snprintf(b, sizeof b, "retro5: font 0x%lx %s%s\n",
                        (unsigned long)fid, xlfd_hint, sym ? "  [symbol->X]" : ""); if (k>0) write(2,b,k); }
    } else {
        r5_bind_helpers();
        for (p = 0; p < fs->n_properties; p++)
            if (fs->properties[p].name == R5_XA_FONT) { nameatom = (Atom)fs->properties[p].card32; break; }
        if (nameatom && r5_XGetAtomName && (xlfd = r5_XGetAtomName(dpy, nameatom)) != 0)
            r5_parse_xlfd(xlfd, family, (int)sizeof family, &bold, &italic, &sym);
        else family[0] = 0;
    }

    slot->id = fid; slot->used = 1; slot->passthrough = sym;
    slot->family = r5_family_for(family, mono);
    slot->slant  = italic ? CAIRO_FONT_SLANT_ITALIC : CAIRO_FONT_SLANT_NORMAL;
    slot->weight = bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL;
    /* cairo em size from the X pixel height. 0.92 keeps our glyphs a touch tighter than the box,
       matching how a modern UI font sits vs. a bitmap face of the same nominal height. The UI scale
       grows it on high-dpi screens; r5_rewrite_metrics grows the measured box by the SAME factor. */
    { int hgt = fs->ascent + fs->descent; if (hgt < 6) hgt = 13; slot->size = hgt * 0.92 * r5_scale(); }
    return slot;
}

/* Fetch the record for a Font XID (draw path has only the id). Cache hit is the norm — the record
 * was interned when the font was loaded; this queries as a fallback for a font we never saw load. */
static R5Font *r5_font_get(Display *dpy, Font fid) {
    XFontStruct *fs;
    R5Font *r;
    int i;
    if (!fid || !dpy) return 0;
    for (i = 0; i < 32; i++)
        if (r5_ftab[i].used && r5_ftab[i].id == fid) return &r5_ftab[i];
    r5_bind_helpers();
    if (!r5_XQueryFont || !(fs = r5_XQueryFont(dpy, fid))) return 0;
    r = r5_font_intern(dpy, fs, 0);
    if (r5_XFreeFontInfo) r5_XFreeFontInfo(0, fs, 1);
    return r;
}
static void r5_font_free(Font fid) {
    int i;
    for (i = 0; i < 32; i++) if (r5_ftab[i].used && r5_ftab[i].id == fid) { r5_ftab[i].used = 0; return; }
}

static void r5_cairo_font(cairo_t *cr, const R5Font *fnt) {
    cz.select_font_face(cr, fnt->family, fnt->slant, fnt->weight);
    cz.set_font_size(cr, fnt->size);
}

/* WP's UI strings are NOT plain Latin-1: some high bytes are WordPerfect codepage / fill characters
 * that Latin-1 would render as garbage. Map the known ones to their intended Unicode here; anything
 * unmapped falls back to Latin-1 (best-effort until a full WP-charset table exists — the RETRO5_TRACE
 * "hibyte" log lists offending bytes to extend this from). 0xFE is WP's field-alignment fill: dialog
 * status lines pad columns with a RUN of it (e.g. "Files: 3<0xFE…>Dirs: 7"), so it must be a SPACE,
 * not Latin-1 'þ'. */
static unsigned r5_wp_codepoint(unsigned char c) {
    switch (c) {
        case 0xFE: return 0x20;                          /* WP fill / hard space -> space (not 'þ') */
        default:   return c;                             /* Latin-1 fallback */
    }
}

/* X text is a WP codepage; cairo wants UTF-8. Convert so a high byte can't poison the context. This
 * is the SINGLE conversion point, used by both the metric rewrite and rendering, so any remap here
 * keeps measured widths and drawn glyphs consistent. */
static int r5_latin1_utf8(const char *s, int len, char *out, int outsz) {
    int i, o = 0;
    for (i = 0; i < len && o < outsz - 3; i++) {
        unsigned char c = (unsigned char)s[i];
        unsigned cp = (c < 0x80) ? (unsigned)c : r5_wp_codepoint(c);
        if (cp < 0x80) out[o++] = (char)cp;
        else if (cp < 0x800) {
            out[o++] = (char)(0xC0 | (cp >> 6));
            out[o++] = (char)(0x80 | (cp & 0x3F));
        } else {
            out[o++] = (char)(0xE0 | (cp >> 12));
            out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[o++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    out[o] = 0;
    return o;
}

/* r5_dpy (the stashed Display for the no-Display metrics calls) is defined up by r5_scale(). */

/* One persistent 1x1 image context for measuring (no per-call surface churn). */
static cairo_t *r5_measure_cr;
static double r5_advance(const R5Font *fnt, const char *s, int len) {
    char buf[1100]; cairo_text_extents_t te;
    if (!r5_measure_cr) {
        cairo_surface_t *ms = cz.image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
        if (!ms) return -1;
        r5_measure_cr = cz.create(ms);
        cz.surface_destroy(ms);
        if (!r5_measure_cr) return -1;
    }
    if (len < 0) len = 0; if (len > 500) len = 500;
    r5_latin1_utf8(s, len, buf, sizeof buf);
    r5_cairo_font(r5_measure_cr, fnt);
    cz.text_extents(r5_measure_cr, buf, &te);
    if (cz.status(r5_measure_cr)) {                      /* poisoned -> rebuild next time */
        cz.destroy(r5_measure_cr); r5_measure_cr = 0; return -1;
    }
    return te.x_advance;
}

static void r5_pixel_rgb(Display *dpy, unsigned long pixel, double *r, double *g, double *b) {
    XColor c; c.pixel = pixel;
    if (r5x.QueryColor(dpy, DefaultColormap(dpy, DefaultScreen(dpy)), &c))
        { *r = c.red/65535.0; *g = c.green/65535.0; *b = c.blue/65535.0; }
    else { *r = *g = *b = 0; }
}

/* XDrawString and XDrawImageString are TWO DIFFERENT X calls and we keep them as two functions,
 * not one with a mode flag: their whole difference — the background — is exactly the thing each
 * ought to own. What they genuinely share is plumbing (resolve the cairo font, read the GC, build a
 * cairo context on the target drawable, transcode the bytes), and only that lives here.
 *
 * r5_text_setup returns 1 with *t populated — the caller draws, then MUST call r5_text_finish — or 0
 * to fall back to real X. */
typedef struct {
    cairo_surface_t *sf;
    cairo_t         *cr;
    R5Font          *fnt;
    XGCValues        gv;
    char             buf[1100];
} R5Text;

static int r5_text_setup(Display *dpy, Drawable d, GC gc, const char *s, int len, R5Text *t) {
    Window root; int gx, gy; unsigned gw, gh, gbw, gdep;
    t->sf = 0; t->cr = 0;
    if (!r5_skin || !r5_text_active || len <= 0 || !dpy || !d) return 0;   /* inert until main window up */
    if (!r5_xlib() || !r5_cairo()) return 0;
    r5_dpy = dpy;                                        /* stash for the no-Display metrics calls */
    r5_bind_helpers();
    if (!r5_XGetGCValues || !r5_XGetGCValues(dpy, gc,
            GCFont | GCForeground | GCBackground | GCFillStyle, &t->gv)) return 0;
    if (!(t->fnt = r5_font_get(dpy, t->gv.font)) || t->fnt->passthrough) return 0;  /* symbol -> X */
    if (!r5x.GetGeometry(dpy, d, &root, &gx, &gy, &gw, &gh, &gbw, &gdep)) return 0;
    t->sf = cz.xlib_surface_create(dpy, d, DefaultVisual(dpy, DefaultScreen(dpy)), (int)gw, (int)gh);
    if (!t->sf) return 0;
    t->cr = cz.create(t->sf);
    if (!t->cr || cz.status(t->cr)) {
        if (t->cr) cz.destroy(t->cr);
        cz.surface_destroy(t->sf); t->cr = 0; t->sf = 0; return 0;
    }
    r5_cairo_font(t->cr, t->fnt);
    r5_latin1_utf8(s, len > 500 ? 500 : len, t->buf, sizeof t->buf);
    if (r5_trace) {                                      /* codepage probe: log strings with high bytes */
        int i, hi = 0;
        for (i = 0; i < len && i < 64; i++) if ((unsigned char)s[i] >= 0x80) { hi = 1; break; }
        if (hi) {
            char hex[160]; int o = 0, j, n = len < 32 ? len : 32;
            for (j = 0; j < n && o < 150; j++)
                o += snprintf(hex + o, sizeof hex - o, "%02x ", (unsigned char)s[j]);
            char b[300]; int k = snprintf(b, sizeof b, "hibyte fam=%s len=%d hex=%s\n",
                t->fnt->family ? t->fnt->family : "?", len, hex);
            if (k > 0) write(2, b, (size_t)k);
        }
    }
    return 1;
}

static void r5_text_finish(R5Text *t) {
    if (t->sf) cz.surface_flush(t->sf);
    if (t->cr) cz.destroy(t->cr);
    if (t->sf) cz.surface_destroy(t->sf);
    t->cr = 0; t->sf = 0;
}

/* Glyph color = GC foreground, dimmed when the GC is INSENSITIVE. Motif draws disabled text with a
 * non-solid fill: XmLabel's insensitive_GC is FillTiled with the "50_foreground" pixmap (a 50%
 * foreground-over-background dither); other widgets use a stipple. Either way X paints the glyph in a
 * half-tone. Our solid cairo glyphs ignore the pattern, so we detect any non-FillSolid GC and
 * reproduce the look by blending the foreground halfway to the background — which is exactly the 50%
 * the "50_foreground" tile encodes. This is what makes disabled menu items, buttons and labels read
 * as greyed. Shared by both text calls. */
static void r5_text_source(Display *dpy, R5Text *t) {
    double fr, fg, fb;
    r5_pixel_rgb(dpy, t->gv.foreground, &fr, &fg, &fb);
    if (t->gv.fill_style != FillSolid) {                 /* FillTiled / FillStippled = insensitive */
        double br, bgc, bb;
        r5_pixel_rgb(dpy, t->gv.background, &br, &bgc, &bb);
        fr = fr * 0.5 + br * 0.5; fg = fg * 0.5 + bgc * 0.5; fb = fb * 0.5 + bb * 0.5;
    }
    cz.set_source_rgb(t->cr, fr, fg, fb);
}

/* --- the interposed X entry points --- */
static void (*r5_real_DrawString)(Display *, Drawable, GC, int, int, const char *, int);
static void (*r5_real_DrawImageString)(Display *, Drawable, GC, int, int, const char *, int);
static int  (*r5_real_FreeFont)(Display *, XFontStruct *);
static XFontStruct *(*r5_real_LoadQueryFont)(Display *, const char *);
static XFontStruct *(*r5_real_QueryFont)(Display *, XID);

/* Text-draw redirection. When a taken-over expose wants a Motif routine's TEXT to land in its back
 * buffer instead of on the window (so the whole widget can be presented in one flicker-free blit),
 * it points r5_redir_from at the window and r5_redir_to at the pixmap for the duration of the call.
 * Both X text entry points rewrite that one drawable, so the glyphs follow into the buffer. */
static Drawable r5_redir_from, r5_redir_to;
#define R5_REDIR(d) do { if (r5_redir_from && (d) == r5_redir_from) (d) = r5_redir_to; } while (0)

/* XDrawString — TRANSPARENT, per X: paint only the glyphs, never touch the background. Whatever the
 * caller already put behind the text (a Motif expose clears the widget first; a double-buffered
 * painter of ours draws the label onto its own fresh face) shows through the antialiased edges. */
void retro5_XDrawString(Display *dpy, Drawable d, GC gc, int x, int y, const char *s, int len) {
    R5Text t;
    R5_REDIR(d);
    if (r5_text_setup(dpy, d, gc, s, len, &t)) {
        r5_text_source(dpy, &t);
        cz.move_to(t.cr, x, y);                          /* X (x,y) is the glyph baseline */
        cz.show_text(t.cr, t.buf);
        r5_text_finish(&t);
        return;
    }
    if (!r5_real_DrawString) *(void **)&r5_real_DrawString = r5_realsym("XDrawString");
    if (r5_real_DrawString) r5_real_DrawString(dpy, d, gc, x, y, s, len);
}

/* XDrawImageString — OPAQUE, per X: fill the glyph box with the GC BACKGROUND, then paint the
 * glyphs. That is image-text semantics exactly, and because the fill precedes the glyphs on a fresh
 * box each call it is inherently idempotent — a label redrawn in place never accumulates. */
void retro5_XDrawImageString(Display *dpy, Drawable d, GC gc, int x, int y, const char *s, int len) {
    R5Text t;
    R5_REDIR(d);
    if (r5_text_setup(dpy, d, gc, s, len, &t)) {
        cairo_text_extents_t te;
        double br, bg, bb;
        cz.text_extents(t.cr, t.buf, &te);
        r5_pixel_rgb(dpy, t.gv.background, &br, &bg, &bb);
        cz.set_source_rgb(t.cr, br, bg, bb);
        cz.rectangle(t.cr, x - 1, y - t.fnt->size, te.x_advance + 3, t.fnt->size * 1.35);
        cz.fill(t.cr);
        r5_text_source(dpy, &t);
        cz.move_to(t.cr, x, y);
        cz.show_text(t.cr, t.buf);
        r5_text_finish(&t);
        return;
    }
    if (!r5_real_DrawImageString) *(void **)&r5_real_DrawImageString = r5_realsym("XDrawImageString");
    if (!r5_real_DrawImageString) *(void **)&r5_real_DrawImageString =
                                      r5_realsym("XDrawImageString");
    if (r5_real_DrawImageString) r5_real_DrawImageString(dpy, d, gc, x, y, s, len);
}

/* XDrawLine — redirect-aware passthrough. The ONLY reason we hook it: Motif draws a menu item's
 * mnemonic underline with XDrawLine (XmString.c: `XDrawLine(d,w,gc,ub,y,ue,y)`), and our menu
 * double-buffer must catch that line into the back buffer or the blit erases it. Outside a redirect
 * (r5_redir_from == 0) R5_REDIR is a no-op and this is an ordinary XDrawLine — no change anywhere. */
static int (*r5_real_DrawLine)(Display *, Drawable, GC, int, int, int, int);
void retro5_XDrawLine(Display *dpy, Drawable d, GC gc, int x1, int y1, int x2, int y2) {
    R5_REDIR(d);
    if (!r5_real_DrawLine) *(void **)&r5_real_DrawLine = r5_realsym("XDrawLine");
    if (r5_real_DrawLine) r5_real_DrawLine(dpy, d, gc, x1, y1, x2, y2);
}

/* THE fix for the startup hang. Rewrite a just-loaded font's WIDTH metrics — per_char[].width plus
 * min/max_bounds.width — to our cairo font's advances, in place. That makes WP see ONE consistent
 * font model: native XTextWidth/XTextExtents (which merely sum per_char) now return cairo widths for
 * free, and Motif's widget/menu geometry — which reads per_char AND max_bounds.width — agrees with
 * them, so its size negotiation converges instead of re-measuring "Program" forever (root cause
 * found in gdb: cairo XTextWidth vs native max_bounds.width disagreed -> non-convergent loop).
 *
 * Vertical metrics are scaled by the UI scale (a no-op at 1.0), so line heights track the enlarged
 * glyphs on high-dpi screens and stay put on stock ones. Symbol/pi fonts and multi-byte (fontset)
 * fonts are left entirely alone. This runs at font-LOAD time, does only in-memory edits + cairo
 * measurement on an image surface (no X traffic, no dlsym), so it is safe even inside WP's startup
 * handshake — and it must run then, because that is when the fonts load. */
static void r5_rewrite_metrics(Display *dpy, XFontStruct *fs, const char *xlfd_hint) {
    R5Font *fnt;
    unsigned c, first, last;
    int minw = 0x7fff, maxw = 0;
    if (!r5_skin || !r5_text || !fs || !r5_cairo()) return;
    if (fs->min_byte1 || fs->max_byte1) return;          /* multi-byte grid: not our single-byte path */
    r5_dpy = dpy;
    fnt = r5_font_intern(dpy, fs, xlfd_hint);
    if (!fnt || fnt->passthrough) return;                /* symbol/pi font -> keep native glyph metrics */

    first = fs->min_char_or_byte2;
    last  = fs->max_char_or_byte2;
    if (fs->per_char && last >= first) {
        for (c = first; c <= last; c++) {
            char ch = (char)c;
            double a = r5_advance(fnt, &ch, 1);
            int w = a > 0 ? (int)(a + 0.5) : 0;
            XCharStruct *cs = &fs->per_char[c - first];
            cs->lbearing = 0; cs->rbearing = (short)w; cs->width = (short)w;
            if (w < minw) minw = w;
            if (w > maxw) maxw = w;
        }
        if (minw > maxw) minw = maxw = 0;
        fs->min_bounds.width = (short)minw;
        fs->max_bounds.width = (short)maxw;
    } else {                                             /* fixed-width font: keep uniform, cairo-sized */
        char ch = 'n';
        double a = r5_advance(fnt, &ch, 1);
        if (a > 0) fs->min_bounds.width = fs->max_bounds.width = (short)(a + 0.5);
    }

    /* Grow the HEIGHT metrics by the UI scale too. Widths already scaled (they are cairo advances at
     * the scaled render size); the vertical metrics are what WP reads for row/control height and the
     * text baseline, so without this our enlarged glyphs would be taller than the box WP reserved and
     * clip. At scale 1.0 this is a no-op, so stock-dpi displays are untouched. */
    {
        double s = r5_scale();
        if (s > 1.0001) {
            fs->ascent  = (int)(fs->ascent  * s + 0.5);
            fs->descent = (int)(fs->descent * s + 0.5);
            fs->max_bounds.ascent  = (short)(fs->max_bounds.ascent  * s + 0.5);
            fs->max_bounds.descent = (short)(fs->max_bounds.descent * s + 0.5);
            fs->min_bounds.ascent  = (short)(fs->min_bounds.ascent  * s + 0.5);
            fs->min_bounds.descent = (short)(fs->min_bounds.descent * s + 0.5);
        }
    }
}

XFontStruct *retro5_XLoadQueryFont(Display *dpy, const char *name) {
    XFontStruct *fs = r5_real_LoadQueryFont ? r5_real_LoadQueryFont(dpy, name) : 0;
    if (fs) r5_rewrite_metrics(dpy, fs, name);           /* name is the XLFD WP asked for */
    return fs;
}
XFontStruct *retro5_XQueryFont(Display *dpy, XID fid) {
    XFontStruct *fs = r5_real_QueryFont ? r5_real_QueryFont(dpy, fid) : 0;
    if (fs) r5_rewrite_metrics(dpy, fs, 0);              /* XLFD from the font's own property */
    return fs;
}
int retro5_XFreeFont(Display *dpy, XFontStruct *fs) {
    if (fs) r5_font_free(fs->fid);
    if (!r5_real_FreeFont) *(void **)&r5_real_FreeFont = r5_realsym("XFreeFont");
    return r5_real_FreeFont ? r5_real_FreeFont(dpy, fs) : 0;
}

/* ---- EWMH / _NET_WM hints on WP's Motif top-levels (RETRO5_EWMH) -------------------------------
 * WP8's Motif (1.2.4, 1998) predates the EWMH/_NET_WM spec, so its frames carry only ICCCM +
 * _MOTIF_WM_HINTS. Modern window managers then can't associate a window with its process, group it
 * in the taskbar, or type it (normal vs dialog) — they guess, often wrongly. We interpose
 * XtRealizeWidget and, once a top-level shell has its X window, stamp the EWMH properties the WM
 * wants. Fail-safe by construction: the real XtRealizeWidget always runs first, and any misstep in
 * the stamp just skips it. This fires while WP builds its UI — long after the SIGALRM startup IPC
 * handshake — so binding the remaining real X calls lazily here is safe (no signal-context dlsym).
 *
 * 8.0 only: 8.0 dynamically links Xt, so XtRealizeWidget has a GOT slot we interpose. 8.1 statically
 * links Xt (no GOT) and would need an inline detour of the static entry — deferred. */
static int r5_ewmh = 1;                     /* RETRO5_EWMH=0 disables */
#ifndef XA_ATOM
#define XA_ATOM              ((Atom)4)
#define XA_CARDINAL          ((Atom)6)
#define XA_STRING            ((Atom)31)
#define XA_WM_CLIENT_MACHINE ((Atom)36)
#endif
static void    (*r5_real_XtRealizeWidget)(void *);
static Window  (*r5_real_XtWindow)(void *);
static Display *(*r5_real_XtDisplayOfObject)(void *);
static int     (*r5_real_XChangeProperty)(Display *, Window, Atom, Atom, int, int,
                                          const unsigned char *, int);
static Atom    (*r5_real_XInternAtom)(Display *, const char *, Bool);
static Status  (*r5_real_XGetWindowAttributes)(Display *, Window, XWindowAttributes *);
static int     (*r5_real_XQueryTree)(Display *, Window, Window *, Window *, Window **, unsigned int *);
static Bool    (*r5_real_XGetTransientForHint)(Display *, Window, Window *);
static int     (*r5_real_XFreeXlib)(void *);
static int     r5_ewmh_bound;

static void r5_ewmh_bind(void) {
    if (r5_ewmh_bound) return;
    r5_ewmh_bound = 1;
    if (!r5_real_XtRealizeWidget) *(void **)&r5_real_XtRealizeWidget = r5_realsym("XtRealizeWidget");
    *(void **)&r5_real_XtWindow             = r5_realsym("XtWindow");
    *(void **)&r5_real_XtDisplayOfObject    = r5_realsym("XtDisplayOfObject");
    *(void **)&r5_real_XChangeProperty      = r5_realsym("XChangeProperty");
    *(void **)&r5_real_XInternAtom          = r5_realsym("XInternAtom");
    *(void **)&r5_real_XGetWindowAttributes = r5_realsym("XGetWindowAttributes");
    *(void **)&r5_real_XQueryTree           = r5_realsym("XQueryTree");
    *(void **)&r5_real_XGetTransientForHint = r5_realsym("XGetTransientForHint");
    *(void **)&r5_real_XFreeXlib            = r5_realsym("XFree");
}

static void r5_stamp_ewmh(Display *dpy, Window win) {
    XWindowAttributes wa;
    Window root = 0, parent = 0, *kids = 0, tf = 0;
    unsigned int nk = 0;
    Atom a_pid, a_wtype, a_wnormal, a_wdialog, wtype;
    long pid;
    char host[256];

    if (!dpy || !win || !r5_real_XChangeProperty || !r5_real_XInternAtom) return;

    /* stamp only real, WM-managed top-levels: skip override-redirect (menus, tooltips, combo
       popups) and any window whose parent is not the root (i.e. a plain child widget). At realize
       time a shell's window still has root as its parent — before the WM reparents it. */
    if (r5_real_XGetWindowAttributes) {
        if (!r5_real_XGetWindowAttributes(dpy, win, &wa)) return;
        if (wa.override_redirect) return;
    }
    if (r5_real_XQueryTree) {
        if (!r5_real_XQueryTree(dpy, win, &root, &parent, &kids, &nk)) return;
        if (kids && r5_real_XFreeXlib) r5_real_XFreeXlib(kids);
        if (root && parent && parent != root) return;
    }

    a_pid     = r5_real_XInternAtom(dpy, "_NET_WM_PID", False);
    a_wtype   = r5_real_XInternAtom(dpy, "_NET_WM_WINDOW_TYPE", False);
    a_wnormal = r5_real_XInternAtom(dpy, "_NET_WM_WINDOW_TYPE_NORMAL", False);
    a_wdialog = r5_real_XInternAtom(dpy, "_NET_WM_WINDOW_TYPE_DIALOG", False);

    /* _NET_WM_PID — and WM_CLIENT_MACHINE, which EWMH requires alongside it for the PID to be honored */
    pid = (long)getpid();
    if (a_pid) r5_real_XChangeProperty(dpy, win, a_pid, XA_CARDINAL, 32,
                                       PropModeReplace, (const unsigned char *)&pid, 1);
    if (gethostname(host, sizeof host - 1) == 0) {
        host[sizeof host - 1] = 0;
        r5_real_XChangeProperty(dpy, win, XA_WM_CLIENT_MACHINE, XA_STRING, 8,
                                PropModeReplace, (const unsigned char *)host, (int)strlen(host));
    }

    /* window type: DIALOG when the shell is transient-for another window (a Motif *Dialog),
       else NORMAL (the main document frame). */
    wtype = a_wnormal;
    if (r5_real_XGetTransientForHint && r5_real_XGetTransientForHint(dpy, win, &tf) && tf && a_wdialog)
        wtype = a_wdialog;
    if (a_wtype && wtype)
        r5_real_XChangeProperty(dpy, win, a_wtype, XA_ATOM, 32,
                                PropModeReplace, (const unsigned char *)&wtype, 1);
}

void retro5_XtRealizeWidget(void *w) {
    r5_ewmh_bind();
    if (r5_real_XtRealizeWidget) r5_real_XtRealizeWidget(w);   /* realize FIRST — window now exists */
    if (!r5_ewmh || !w || !r5_real_XtWindow || !r5_real_XtDisplayOfObject) return;
    {
        Window   win = r5_real_XtWindow(w);
        Display *dpy = r5_real_XtDisplayOfObject(w);
        if (win && dpy) r5_stamp_ewmh(dpy, win);
    }
}

/* Resolve EVERYTHING our hooks could ever need, eagerly, at library init — before WP runs. This is
 * the whole safety argument for the text layer: a hook that fires while WP's SIGALRM startup
 * handshake is live must NOT touch the dynamic linker (dlsym / lazy PLT bind take dl_load_lock,
 * which is not async-signal-safe -> deadlock). So we pre-bind the X vtable, the Xt/X helper calls,
 * and the five real text entry points now, while nothing is racing. cairo is dlopen'd RTLD_NOW so
 * its own PLTs are fully bound at load too. After this returns, no hook can reach the linker. */
static void r5_resolve_reals(void) {
    r5_xlib();                                            /* binds the whole X draw/query vtable */
    r5_bind_helpers();                                    /* XQueryFont / XGetGCValues / ...      */
    /* r5_realsym, NOT dlsym(RTLD_DEFAULT): every one of these is a symbol whose GOT we patch, so
       RTLD_DEFAULT would return our own PLT stub and the hook would call itself. */
    *(void **)&r5_real_DrawString      = r5_realsym("XDrawString");
    *(void **)&r5_real_DrawImageString = r5_realsym("XDrawImageString");
    *(void **)&r5_real_FreeFont        = r5_realsym("XFreeFont");
    *(void **)&r5_real_LoadQueryFont   = r5_realsym("XLoadQueryFont");
    *(void **)&r5_real_QueryFont       = r5_realsym("XQueryFont");
}

/* ---- the two reusable takeover tables ----
 * A per-binary takeoverXxx() is nothing but these two tables plus (for static hosts) an R5XSyms.
 * Everything they point at is shared, binary-independent code.
 * (R5Entry / R5Import / R5Method are now defined in r5syms.h, included at the top of this file.) */
static void takeover_entries(const R5Entry *t, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++)
        patch_entry(t[i].va, t[i].guard, t[i].glen, t[i].target);
}

static void takeover_imports(const R5Import *t, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) {
        int ok = patch_import(t[i].plt, t[i].got, t[i].target);
        if (r5_trace) {
            char b[96];
            int k = snprintf(b, sizeof b, "retro5: import takeover %-16s %s\n",
                             t[i].name, ok ? "ok" : "SKIPPED (guard mismatch)");
            if (k > 0) write(2, b, (size_t)k);
        }
    }
}

static void takeover_methods(const R5Method *t, unsigned n) {
    unsigned i;
    for (i = 0; i < n; i++) {
        int ok = patch_method(t[i].class_rec, R5_EXPOSE_OFF, t[i].expect, t[i].target, t[i].saved);
        if (r5_trace) {
            char b[96];
            int k = snprintf(b, sizeof b, "retro5: expose takeover %-16s %s\n",
                             t[i].name, ok ? "ok" : "SKIPPED (guard mismatch)");
            if (k > 0) write(2, b, (size_t)k);
        }
    }
}

/* ======================================================================================= *
 *  Widget-level takeover — owning a button's whole appearance
 * ======================================================================================= *
 * The primitives above restyle every widget's EDGES, but they cannot round a button's CORNERS: the
 * corner pixels belong to the widget's own background fill, which Motif paints before it ever calls
 * a shadow primitive. To round them we need the widget, so we take over its class `expose` method.
 *
 * We WRAP rather than replace: run the original first, then paint on top. Last writer wins, so
 * nothing we draw is undone — and WP keeps rendering its own icon (XmNlabelPixmap, insensitive
 * stipple, label layout), which a full replacement would force us to reimplement for no visual
 * gain. The original's own bevel call lands back in retro5_XmDrawShadows, so the frame is already
 * ours by the time we get control.
 *
 * Reusable by construction: it keys off nothing but the widget, so the same painter serves
 * XmDrawnButton, XmPushButton and friends, in xwp or in any of the helper binaries. */

/* GC for an arbitrary pixel value (the parent's background), memoized. */
static struct { unsigned long pix; GC gc; } r5_pixgc[8];
static int r5_pixgc_n;
static GC r5_gc_for_pixel(Display *dpy, Drawable d, unsigned long pix) {
    XGCValues v;
    int i;
    for (i = 0; i < r5_pixgc_n; i++)
        if (r5_pixgc[i].pix == pix) return r5_pixgc[i].gc;
    if (r5_pixgc_n >= 8) return 0;
    v.foreground = pix;
    r5_pixgc[r5_pixgc_n].gc  = r5x.CreateGC(dpy, d, GCForeground, &v);
    r5_pixgc[r5_pixgc_n].pix = pix;
    return r5_pixgc[r5_pixgc_n++].gc;
}

/* ---- the double buffer ----
 * THE LAW: any expose we take over, we re-make completely — and we do it off-screen. Every taken-over
 * painter draws into a back-buffer Pixmap (window depth, window size) and blits the finished frame to
 * the window in a single XCopyArea. The window is therefore only ever written once per repaint, with a
 * complete image, so there is no flicker (no intermediate face/border/icon/label states are ever seen)
 * and no tearing between our passes. Both X drawing (FillRectangle, DrawPoints, CopyArea/Plane) and
 * cairo (text, indicators) target the SAME pixmap: the X calls take the Drawable directly, cairo gets
 * an xlib surface on it, so one buffer serves every draw primitive the painters use.
 *
 * The blit GC has graphics_exposures OFF: a full-cover copy would otherwise emit NoExpose events, and
 * (if the pixmap were ever smaller than the window) GraphicsExpose events that would trigger another
 * expose — a repaint loop. We never want the copy itself to generate expose traffic. */
typedef struct {
    Display        *dpy;
    Window          win;
    Pixmap          buf;
    unsigned        w, h;
    cairo_surface_t *sf;    /* lazily created — only if a caller asks for cairo */
    cairo_t         *cr;
    int             ok;
} R5Canvas;

static GC r5_blit_gc;
static GC r5_get_blit_gc(Display *dpy, Drawable d) {
    if (!r5_blit_gc) {
        XGCValues v;
        v.graphics_exposures = False;
        r5_blit_gc = r5x.CreateGC(dpy, d, GCGraphicsExposures, &v);
    }
    return r5_blit_gc;
}

/* Begin a frame: allocate the back buffer at the window's depth and size. Returns 0 (and leaves the
 * canvas inert) if anything is missing, so callers can just fall through to their non-buffered path. */
static int r5_canvas_begin(R5Canvas *c, Display *dpy, Window win, unsigned w, unsigned h) {
    Window root; int rx, ry; unsigned rw, rh, bw, dep;
    c->dpy = 0; c->win = 0; c->buf = 0; c->w = 0; c->h = 0; c->sf = 0; c->cr = 0; c->ok = 0;
    if (!dpy || !win || w < 1 || h < 1 || !r5_xlib()) return 0;
    if (!r5x.GetGeometry(dpy, win, &root, &rx, &ry, &rw, &rh, &bw, &dep)) return 0;
    c->buf = r5x.CreatePixmap(dpy, win, w, h, dep);
    if (!c->buf) return 0;
    c->dpy = dpy; c->win = win; c->w = w; c->h = h; c->ok = 1;
    return 1;
}

/* A cairo context bound to the back buffer, made on first use. NULL if cairo is unavailable — an
 * X-only painter never triggers the surface allocation. */
static cairo_t *r5_canvas_cairo(R5Canvas *c) {
    if (c->cr) return c->cr;
    if (!c->ok || !r5_cairo()) return 0;
    c->sf = cz.xlib_surface_create(c->dpy, c->buf,
                                   DefaultVisual(c->dpy, DefaultScreen(c->dpy)), (int)c->w, (int)c->h);
    if (!c->sf) return 0;
    c->cr = cz.create(c->sf);
    if (!c->cr || cz.status(c->cr)) {
        if (c->cr) cz.destroy(c->cr);
        cz.surface_destroy(c->sf);
        c->cr = 0; c->sf = 0;
        return 0;
    }
    return c->cr;
}

/* Present the finished frame: flush cairo, blit the given sub-rectangle to the window, free the
 * buffer. Pass the whole widget (0,0,w,h) for a full-widget painter, or just the region we own for a
 * partial takeover (e.g. a toggle indicator cell, where Motif still paints the label). */
static void r5_canvas_commit(R5Canvas *c, int x, int y, unsigned w, unsigned h) {
    GC gc;
    if (!c->ok) return;
    if (c->cr) {
        cz.surface_flush(c->sf);
        cz.destroy(c->cr);
        cz.surface_destroy(c->sf);
        c->cr = 0; c->sf = 0;
    }
    if (w && h && (gc = r5_get_blit_gc(c->dpy, c->win)))
        r5x.CopyArea(c->dpy, c->buf, c->win, gc, x, y, w, h, x, y);
    r5x.FreePixmap(c->dpy, c->buf);
    c->buf = 0; c->ok = 0;
}

/* Read a widget's `background` pixel (the resource, via the real XtGetValues). */
static int r5_bg_pixel(void *w, unsigned long *out) {
    R5Arg a;
    unsigned long bg = 0;
    if (!w) return 0;
    if (!g_XtGetValues) g_XtGetValues = (void (*)(void *, R5Arg *, unsigned))
                                        dlsym(RTLD_DEFAULT, "XtGetValues");
    if (!g_XtGetValues) return 0;
    a.name = (char *)"background";
    a.value = (long)&bg;
    g_XtGetValues(w, &a, 1);
    *out = bg;
    return 1;
}

/* Carve the four corners out of a widget, in its PARENT's background color — which is what turns
 * our rounded 1px frame into a genuinely rounded button instead of a rounded outline sitting on a
 * square face. Only the 3 pixels outside the frame's arc are touched per corner, so no icon, label
 * or focus ring can ever be clipped. */
/* Carve the four corners of a `ww`x`hh` widget out of drawable `d`, in widget `w`'s PARENT background
 * color — which turns our rounded 1px frame into a genuinely rounded button rather than a rounded
 * outline on a square face. `d` is the DRAW TARGET (the back buffer when double-buffering, the window
 * for the Motif-fallback path); the parent color is read off the live widget regardless. Only the 3
 * pixels outside the frame's arc are touched per corner, so no icon/label/focus ring is ever clipped. */
static void r5_carve_corners(Display *dpy, Drawable d, void *w, unsigned ww, unsigned hh) {
    unsigned long bg;
    void *parent;
    GC gc;
    XPoint p[12];
    int i = 0, x1, y1;
    if (ww < 6 || hh < 6) return;
    parent = *(void **)((char *)w + 8);                   /* core.parent */
    if (!parent || range_unmapped(parent, 12) || *(void **)parent != parent) return;
    if (!r5_bg_pixel(parent, &bg)) return;
    if (!(gc = r5_gc_for_pixel(dpy, d, bg))) return;

    x1 = (int)ww - 1; y1 = (int)hh - 1;
    p[i].x = 0;      p[i++].y = 0;                        /* top-left    */
    p[i].x = 1;      p[i++].y = 0;
    p[i].x = 0;      p[i++].y = 1;
    p[i].x = x1;     p[i++].y = 0;                        /* top-right   */
    p[i].x = x1 - 1; p[i++].y = 0;
    p[i].x = x1;     p[i++].y = 1;
    p[i].x = 0;      p[i++].y = y1;                       /* bottom-left */
    p[i].x = 1;      p[i++].y = y1;
    p[i].x = 0;      p[i++].y = y1 - 1;
    p[i].x = x1;     p[i++].y = y1;                       /* bottom-right*/
    p[i].x = x1 - 1; p[i++].y = y1;
    p[i].x = x1;     p[i++].y = y1 - 1;
    r5x.DrawPoints(dpy, d, gc, p, i, CoordModeOrigin);
}

/* Corner-carve on the WINDOW — the fallback path, when Motif drew the widget itself (unbuffered) and
 * we only round the corners on top. */
static void retro5_round_widget(void *w) {
    Display *dpy;
    Window win, root;
    unsigned int ww, hh, bw, dep;
    int wx, wy;
    if (!r5_skin || !w || !r5_xlib()) return;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return;
    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bw, &dep)) return;
    r5_carve_corners(dpy, win, w, ww, hh);
}

/* Read several resources off a widget in one XtGetValues. */
static void r5_get(void *w, R5Arg *args, unsigned n) {
    if (!g_XtGetValues) g_XtGetValues = (void (*)(void *, R5Arg *, unsigned))
                                        dlsym(RTLD_DEFAULT, "XtGetValues");
    if (g_XtGetValues) g_XtGetValues(w, args, n);
}

/* ======================================================================================= *
 *  Icon system — content-addressed replacement + disabled greying
 * ======================================================================================= *
 * Icons are matched by the PIXEL CONTENT of WP's own bitmap (a hash), not by button identity, so a
 * mapping is stable across button position, name and build. RETRO5_ICON_DUMP logs each icon's hash
 * so a `hash -> file` map can be built by eye; RETRO5_ICONS points at that map file (lines:
 * "<hexhash> <path>", '#' comments). A matched icon is replaced by the file (rendering wired in a
 * following step); either way a disabled button's icon is drawn greyed — native OR replacement. */
static int         r5_icon_dump;            /* RETRO5_ICON_DUMP: emit config skeleton lines */
static const char *r5_icons_cfg;            /* RETRO5_ICONS: hash->file map path */
static struct { uint32_t hash; char file[256]; } r5_icon_map[128];
static int         r5_icon_map_n = -1;      /* -1 = not yet loaded */

/* Dump de-dup: distinct buttons carry their own pixmap copy of a shared icon, so the same HASH is
 * seen on many pixmap XIDs. The skeleton wants each hash ONCE. */
static uint32_t    r5_dump_seen[256];
static int         r5_dump_seen_n;
static int r5_dump_first_time(uint32_t h) {
    int i;
    for (i = 0; i < r5_dump_seen_n; i++) if (r5_dump_seen[i] == h) return 0;
    if (r5_dump_seen_n < 256) r5_dump_seen[r5_dump_seen_n++] = h;
    return 1;
}

static void r5_icon_map_load(void) {
    FILE *f; char line[400];
    char dir[256]; size_t dirlen = 0;
    const char *slash;
    if (r5_icon_map_n >= 0) return;                      /* load once */
    r5_icon_map_n = 0;
    if (!r5_icons_cfg || !r5_icons_cfg[0] || !(f = fopen(r5_icons_cfg, "r"))) return;
    /* Directory of the config file — RELATIVE icon paths resolve against it, so the map file is
     * portable (commit it next to its icons; no absolute /home/... paths needed). */
    if ((slash = strrchr(r5_icons_cfg, '/')) != 0) {
        dirlen = (size_t)(slash - r5_icons_cfg) + 1;     /* keep the trailing '/' */
        if (dirlen < sizeof dir) memcpy(dir, r5_icons_cfg, dirlen); else dirlen = 0;
    }
    while (fgets(line, sizeof line, f) && r5_icon_map_n < 128) {
        unsigned long h; char path[256]; char *dst;
        if (line[0] == '#' || line[0] == '\n') continue;
        /* "<hexhash> <file-or-'-'> [hint...]" — '-' means not mapped yet (skeleton row); the hint
         * text after the file is documentation for the human and ignored here. */
        if (sscanf(line, "%lx %255s", &h, path) == 2 && strcmp(path, "-") != 0) {
            dst = r5_icon_map[r5_icon_map_n].file;
            if (path[0] != '/' && dirlen) {              /* relative -> prefix the config's dir */
                int k = snprintf(dst, 256, "%.*s%s", (int)dirlen, dir, path);
                if (k <= 0 || k >= 256) continue;
            } else {
                strncpy(dst, path, 255); dst[255] = 0;
            }
            r5_icon_map[r5_icon_map_n].hash = (uint32_t)h;
            r5_icon_map_n++;
        }
    }
    fclose(f);
}
static const char *r5_icon_lookup(uint32_t h) {
    int i;
    r5_icon_map_load();
    for (i = 0; i < r5_icon_map_n; i++) if (r5_icon_map[i].hash == h) return r5_icon_map[i].file;
    return 0;
}

/* FNV-1a over the icon's pixels (via XGetPixel, so row padding can't destabilise it) + dims/depth.
 * Same icon content -> same hash, wherever/whenever drawn.
 *
 * Recomputed on EVERY call — deliberately NOT cached by pixmap XID. The palette / dropdown buttons
 * (e.g. the Justification "current selection" face) REUSE one pixmap XID and redraw different content
 * into it as the selection changes, so an XID->hash cache goes stale and shows the previous icon.
 * XGetImage on a ~20x18 pixmap is cheap, and since we took over Motif's border_highlight the button
 * no longer repaints on hover, so re-reading per expose does not flicker. The expensive step (SVG/PNG
 * render) stays cached by (hash,size) in r5_icon_cache, so only the small readback repeats. */
static uint32_t r5_pixmap_hash(Display *dpy, Pixmap pm, unsigned pw, unsigned ph, unsigned pdep) {
    XImage *im;
    uint32_t h = 2166136261u;
    unsigned x, y;
    if (!r5x.GetImage) return 0;
    im = r5x.GetImage(dpy, pm, 0, 0, pw, ph, AllPlanes, ZPixmap);
    if (!im) return 0;
#define R5_FNV(b) do { h ^= (uint32_t)(unsigned char)(b); h *= 16777619u; } while (0)
    R5_FNV(pw); R5_FNV(pw >> 8); R5_FNV(ph); R5_FNV(ph >> 8); R5_FNV(pdep);
    for (y = 0; y < ph; y++)
        for (x = 0; x < pw; x++) {
            unsigned long p = XGetPixel(im, (int)x, (int)y);
            R5_FNV(p); R5_FNV(p >> 8); R5_FNV(p >> 16);
        }
#undef R5_FNV
    XDestroyImage(im);
    return h;
}

/* Blend a 0xRRGGBB toward a bg pixel (TrueColor 24-bit) — t=weight of `rgb`. Returns a pixel value. */
static unsigned long r5_blend_pixel(unsigned rgb, unsigned long bg, double t) {
    double u = 1.0 - t;
    int r = (int)(((rgb >> 16) & 0xff) * t + ((bg >> 16) & 0xff) * u + 0.5);
    int g = (int)(((rgb >>  8) & 0xff) * t + ((bg >>  8) & 0xff) * u + 0.5);
    int b = (int)(((rgb      ) & 0xff) * t + ((bg      ) & 0xff) * u + 0.5);
    return ((unsigned long)r << 16) | ((unsigned long)g << 8) | (unsigned)b;
}

/* Blit a COLOUR icon into `dst` at (ix,iy) GREYED: read it, desaturate each pixel to luminance and
 * fade it toward the widget background, put it back. (TrueColor 24-bit assumed — the WP visual.) */
static int r5_blit_gray_color(Display *dpy, Pixmap pm, Drawable dst, GC gc,
                              unsigned pw, unsigned ph, int ix, int iy, unsigned long bg) {
    XImage *im;
    unsigned x, y;
    double bgr = (bg >> 16) & 0xff, bgg = (bg >> 8) & 0xff, bgb = bg & 0xff;
    if (!r5x.GetImage || !r5x.PutImage) return 0;
    if (!(im = r5x.GetImage(dpy, pm, 0, 0, pw, ph, AllPlanes, ZPixmap))) return 0;
    for (y = 0; y < ph; y++)
        for (x = 0; x < pw; x++) {
            unsigned long p = XGetPixel(im, (int)x, (int)y);
            int lum = (int)((((p >> 16) & 0xff) * 30 + ((p >> 8) & 0xff) * 59 + (p & 0xff) * 11) / 100);
            int r = (int)(lum * 0.55 + bgr * 0.45);      /* desaturate + fade toward bg */
            int g = (int)(lum * 0.55 + bgg * 0.45);
            int b = (int)(lum * 0.55 + bgb * 0.45);
            XPutPixel(im, (int)x, (int)y, ((unsigned long)r << 16) | ((unsigned long)g << 8) | (unsigned)b);
        }
    r5x.PutImage(dpy, dst, gc, im, 0, 0, ix, iy, pw, ph);
    XDestroyImage(im);
    return 1;
}

static int r5_insensitive(void *w);                      /* defined below (toggle section) */

/* The widget's instance name (XtName). Only the generic Motif type here (TBpushButton, ...), so it
 * is a poor icon label — the hint below is what actually identifies a button. Resolved from libXt. */
static char *(*r5_XtName)(void *);
static const char *r5_widget_name(void *w) {
    if (!r5_XtName) *(void **)&r5_XtName = r5_realsym("XtName");
    return r5_XtName ? r5_XtName(w) : 0;
}

/* The button's descriptive name — WP's status-bar hint, e.g. "QuickFind Previous", "Bold". WP hangs
 * it off XmNuserData: a WP control struct whose +0x1c field is a char* to that name. Verified for
 * this build across push/toggle/palette toolbar buttons. This is what lets an icon hash be matched
 * to a file by meaning. Guarded: userData on a non-WP widget would give a bad char*, so we reject a
 * pointer outside the heap rather than deref garbage. */
static const char *r5_widget_hint(void *w) {
    void *ud = 0;
    const char *p;
    R5Arg a[1];
    a[0].name = (char *)"userData"; a[0].value = (long)&ud;
    r5_get(w, a, 1);
    if (!ud) return 0;
    p = *(const char **)((const char *)ud + 0x1c);       /* WP control struct: name/hint pointer */
    if ((uintptr_t)p < 0x08048000 || (uintptr_t)p >= 0x10000000) return 0;  /* not a heap string */
    return p;
}

static int r5_ends_with(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcasecmp(s + ls - lf, suf) == 0;
}

/* ---- the icon seam ----
 * If the icon's content hash is mapped (RETRO5_ICONS), render the mapped file to an X Pixmap of the
 * target size and hand it back to replace WP's own bitmap; a miss returns 0 (WP's pixmap is kept).
 * A PNG is scaled (aspect preserved, centred); an SVG is rendered into the target viewport. The
 * pixmap is backfilled with the button face colour so transparent icon areas blend on the blit.
 * Cached by (hash, tw, th) for process life — each distinct icon+size renders once. */
static struct { uint32_t hash; unsigned tw, th; Pixmap pm; } r5_icon_cache[128];
static int r5_icon_cache_n;

static Pixmap r5_icon_render(Display *dpy, Window win, unsigned dep,
                             uint32_t hash, unsigned tw, unsigned th, unsigned long bg) {
    const char *path;
    int i, drew = 0;
    Pixmap P;
    cairo_surface_t *sf;
    cairo_t *cr;
    Visual *vis;

    if (!hash || !r5_cairo() || !cz.icons_ok) return 0;
    if (tw < 2 || th < 2 || tw > 512 || th > 512) return 0;
    if (!(path = r5_icon_lookup(hash))) return 0;

    for (i = 0; i < r5_icon_cache_n; i++)                /* cached render? */
        if (r5_icon_cache[i].hash == hash && r5_icon_cache[i].tw == tw && r5_icon_cache[i].th == th)
            return r5_icon_cache[i].pm;

    if (!(P = r5x.CreatePixmap(dpy, win, tw, th, dep))) return 0;
    vis = DefaultVisual(dpy, DefaultScreen(dpy));
    sf = cz.xlib_surface_create(dpy, P, vis, (int)tw, (int)th);
    cr = (sf && !cz.surface_status(sf)) ? cz.create(sf) : 0;
    if (!cr || cz.status(cr)) {
        if (cr) cz.destroy(cr);
        if (sf) cz.surface_destroy(sf);
        r5x.FreePixmap(dpy, P);
        return 0;
    }

    cz.set_source_rgb(cr, R5_RD(bg), R5_GD(bg), R5_BD(bg));   /* face backfill for transparency */
    cz.paint(cr);

    if (strncmp(path, "font:", 5) == 0) {
        /* "font:<glyph>[:flags]" — render a character in the UI font, centred. flags: b=bold,
         * i=italic, u=underline. For B/I/U these beat any bitmap: crisp, hinted, theme-matched. */
        const char *spec = path + 5, *p;
        char glyph[16]; int gi = 0, bold = 0, ital = 0, under = 0;
        for (p = spec; *p && *p != ':' && gi < 15; p++) glyph[gi++] = *p;
        glyph[gi] = 0;
        if (*p == ':') for (p++; *p; p++) { if (*p=='b') bold=1; else if (*p=='i') ital=1; else if (*p=='u') under=1; }
        if (gi > 0) {
            cairo_text_extents_t te;
            double fs, gx, gy;
            const char *fam = r5_family_for(0, 0);
            cairo_font_slant_t  sl = ital ? CAIRO_FONT_SLANT_ITALIC : CAIRO_FONT_SLANT_NORMAL;
            cairo_font_weight_t wt = bold ? CAIRO_FONT_WEIGHT_BOLD  : CAIRO_FONT_WEIGHT_NORMAL;
            /* Auto-fit: font SIZE != glyph INK (a cap fills ~0.7 of the em). Measure the ink at a
             * reference size, then scale so the ink fills the target box — the glyph then reads at
             * a consistent visual size whatever its cap-height/width, no hand-tuned multiplier. */
            cz.select_font_face(cr, fam, sl, wt);
            cz.set_font_size(cr, (double)th);                /* reference size */
            cz.text_extents(cr, glyph, &te);
            if (te.height > 0.5 && te.width > 0.5) {
                double sh = (th * 0.66) / te.height;         /* fill ~66% of height ... */
                double sw = (tw * 0.74) / te.width;          /* ... or 74% of width, whichever binds */
                fs = (double)th * (sh < sw ? sh : sw);
                cz.set_font_size(cr, fs);
                cz.text_extents(cr, glyph, &te);             /* re-measure at the real size */
                gx = (tw - te.width) / 2.0 - te.x_bearing;   /* centre by ink box */
                gy = (th - te.height) / 2.0 - te.y_bearing;
                cz.set_source_rgb(cr, R5_RD(0x303030u), R5_GD(0x303030u), R5_BD(0x303030u));
                cz.move_to(cr, gx, gy);
                cz.show_text(cr, glyph);
                if (under) {                                 /* underline bar just below the glyph */
                    double uh = fs * 0.09 + 1.0;
                    cz.rectangle(cr, gx + te.x_bearing, gy + fs * 0.12, te.width, uh);
                    cz.fill(cr);
                }
                drew = 1;
            }
        }
    } else if (r5_ends_with(path, ".png")) {
        cairo_surface_t *img = cz.png_create(path);
        if (img && !cz.surface_status(img)) {
            int iw = cz.img_w(img), ih = cz.img_h(img);
            if (iw > 0 && ih > 0) {
                double s = (double)tw / iw, s2 = (double)th / ih;
                double dw, dh;
                if (s2 < s) s = s2;                      /* fit inside, preserve aspect */
                dw = iw * s; dh = ih * s;
                cz.save(cr);
                cz.translate(cr, (tw - dw) / 2.0, (th - dh) / 2.0);
                cz.scale(cr, s, s);
                cz.set_source_surface(cr, img, 0, 0);
                cz.paint(cr);
                cz.restore(cr);
                drew = 1;
            }
        }
        if (img) cz.surface_destroy(img);
    } else if (r5_rsvg()) {                              /* .svg (and anything non-.png) */
        size_t len = 0;
        unsigned char *data = r5_read_file(path, &len);  /* read bytes ourselves -> no GIO/GFile */
        if (data) {
            void *err = 0, *hdl = rvz.new_from_data(data, len, &err);
            if (hdl) {
                double viewport[4];                      /* RsvgRectangle {x,y,w,h} */
                viewport[0] = 0; viewport[1] = 0; viewport[2] = (double)tw; viewport[3] = (double)th;
                if (rvz.render_document(hdl, cr, viewport, &err)) drew = 1;
                rvz.g_unref(hdl);
            }
            free(data);
        }
    }

    cz.surface_flush(sf);
    cz.destroy(cr);
    cz.surface_destroy(sf);
    if (!drew) { r5x.FreePixmap(dpy, P); return 0; }     /* load/parse failed -> keep WP's own */

    if (r5_trace) {
        char b[320]; int k = snprintf(b, sizeof b, "icon %08x -> %s  %ux%u\n", hash, path, tw, th);
        if (k > 0) write(2, b, (size_t)k);
    }
    if (r5_icon_cache_n < 128) {
        r5_icon_cache[r5_icon_cache_n].hash = hash;
        r5_icon_cache[r5_icon_cache_n].tw   = tw;
        r5_icon_cache[r5_icon_cache_n].th   = th;
        r5_icon_cache[r5_icon_cache_n].pm   = P;
        r5_icon_cache_n++;
    }
    return P;
}

/* ---- highlight takeover ----
 * On EnterWindow/LeaveWindow Motif draws (then erases) its highlight border by calling the widget's
 * border_highlight / border_unhighlight class methods DIRECTLY on the window — outside the expose we
 * own. That is mixed drawing: Motif's border flashes against our fully-painted button, visible as
 * flicker on mouse enter and leave. We replace those two methods with a no-op so the button we
 * painted is never touched on hover; if a hover accent is ever wanted, it belongs in our expose.
 *
 * The two methods are the first slots of XmPrimitiveClassPart, which follows the 116-byte 32-bit
 * CoreClassPart -> +116 and +120 (confirmed live: +124 holds the heap XtTranslations pointer).
 *
 * Patched LAZILY, from the paint path, NOT at load time: Xt resolves class-method inheritance when
 * WP creates the first widget (after our constructor has run), which clobbers any load-time swap of
 * an inherited slot — exactly what silently defeats the resize takeover. By the time expose runs,
 * the class record is fully initialised, so reading the live slot as the guard makes the swap stick.
 */
#define R5_BORDER_HL_OFF   116
#define R5_BORDER_UNHL_OFF 120
static int r5_is_dropdown_item(void *w);                 /* defined in the menu-item section below */
static int (*r5_XClearArea)(Display *, Window, int, int, unsigned, unsigned, int);
/* border_highlight/unhighlight takeover. For toolbar/dialog buttons this is a pure no-op (Motif must
 * not draw its highlight border over the button we fully painted). For a DROPDOWN MENU ITEM we reuse
 * this enter/leave hook the other way: force an Expose so our expose re-runs and re-evaluates the
 * hot-track (the item under the pointer washes subtly). Cheap XClearArea(...,True) just queues the
 * Expose; with the item window's None background it paints nothing itself, so no flash. */
static void retro5_NoHighlight(void *w) {
    if (w && r5_is_dropdown_item(w)) {
        Display *dpy = r5x.XtDisplayOfObject(w);
        Window   win = r5x.XtWindowOfObject(w);
        if (!r5_XClearArea) *(void **)&r5_XClearArea = r5_realsym("XClearArea");
        if (dpy && win && r5_XClearArea) r5_XClearArea(dpy, win, 0, 0, 0, 0, 1);
    }
}

static void *(*r5_XtClass)(void *);
static void  *r5_hl_done[16];
static int    r5_hl_done_n;
static void r5_take_highlight(void *w) {
    void *cls, *saved; int i; uintptr_t hl, unhl;
    if (!r5_XtClass) *(void **)&r5_XtClass = r5_realsym("XtClass");
    if (!r5_XtClass || !w) return;
    cls = r5_XtClass(w);
    if (!cls || range_unmapped((char *)cls + R5_BORDER_UNHL_OFF, 4)) return;
    for (i = 0; i < r5_hl_done_n; i++) if (r5_hl_done[i] == cls) return;  /* this class already done */
    if (r5_hl_done_n < 16) r5_hl_done[r5_hl_done_n++] = cls;
    hl   = *(uintptr_t *)((char *)cls + R5_BORDER_HL_OFF);
    unhl = *(uintptr_t *)((char *)cls + R5_BORDER_UNHL_OFF);
    if (hl   != (uintptr_t)retro5_NoHighlight)
        patch_method((uintptr_t)cls, R5_BORDER_HL_OFF,   hl,   (void *)retro5_NoHighlight, &saved);
    if (unhl != (uintptr_t)retro5_NoHighlight)
        patch_method((uintptr_t)cls, R5_BORDER_UNHL_OFF, unhl, (void *)retro5_NoHighlight, &saved);
    if (r5_trace) {
        char b[96]; int k = snprintf(b, sizeof b, "retro5: highlight takeover class %p\n", cls);
        if (k > 0) write(2, b, (size_t)k);
    }
}

/* Give a window a None background so the server never auto-fills it. WP hot-tracks buttons on hover
 * by calling XtVaSetValues on enter/leave; when set_values asks for redisplay, Xt runs
 * XClearArea(win, 0,0,0,0, True) — clears the WHOLE window to its (grey) background then generates an
 * Expose. That grey clear is a visible flash before our expose repaints (gdb: XClearArea <-
 * XtSetValues <- XtVaSetValues <- WP enter/leave). Per the X spec, XClearArea on a None-background
 * window changes NO contents but still generates the exposures, so our expose redraws over the intact
 * frame: the Expose survives, the flash does not. Only for windows we fully own. */
static int (*r5_XSetWindowBackgroundPixmap)(Display *, Window, Pixmap);
static void r5_win_no_autoclear(Display *dpy, Window win) {
    if (!r5_XSetWindowBackgroundPixmap)
        *(void **)&r5_XSetWindowBackgroundPixmap = r5_realsym("XSetWindowBackgroundPixmap");
    if (r5_XSetWindowBackgroundPixmap) r5_XSetWindowBackgroundPixmap(dpy, win, (Pixmap)None);
}

/* Paint a Label-derived button end to end: face, border, icon. Nothing of Motif's drawing survives
 * — we do not call the original — so the appearance is entirely ours, including the icon blit.
 *
 * The one thing we must not do is blank a button whose content Motif renders some way we do not
 * handle (an XmNexposeCallback, or a text label rather than a pixmap). So the pixmap is read first,
 * and if there is nothing for us to draw we hand the widget back to its original expose rather than
 * paint an empty box. Returns 1 if we painted it. */
static int retro5_paint_button(void *w, int flat_at_rest) {
    Display *dpy;
    Window win, root;
    Pixmap pm = 0, custom;
    unsigned long bg = 0;
    long shadow_type = 0;
    int wx, wy, px, py, sunk, dim;
    unsigned int ww, hh, bw, dep, pw, ph, pbw, pdep;
    R5Canvas cv;
    Drawable dst;
    GC face;
    R5Arg args[3];

    if (!r5_skin || !w || !r5_xlib()) return 0;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return 0;
    r5_take_highlight(w);                                 /* stop Motif's enter/leave border flicker */

    args[0].name = (char *)"labelPixmap"; args[0].value = (long)&pm;
    args[1].name = (char *)"background";  args[1].value = (long)&bg;
    args[2].name = (char *)"shadowType";  args[2].value = (long)&shadow_type;
    r5_get(w, args, 3);

    /* No pixmap -> hand back to Motif (it draws the text label). CRITICAL: Motif's "no pixmap"
     * sentinel is XmUNSPECIFIED_PIXMAP == (Pixmap)2, NOT 0 — every text menu item / dialog button
     * carries labelPixmap==2. Treating 2 as a real pixmap and XGetGeometry'ing it is a BadDrawable,
     * which WP's error handler turns into an immediate exit (this is what crashed on menu open). */
    if (!pm || pm == R5_UNSPECIFIED_PIXMAP) return 0;

    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bw, &dep)) return 0;
    if (!r5x.GetGeometry(dpy, pm, &root, &px, &py, &pw, &ph, &pbw, &pdep)) return 0;
    if (ww < 4 || hh < 4) return 0;
    if (pdep != 1 && pdep != dep) return 0;               /* depth we don't understand -> defer */

    /* Icon identity: hash the content (only when discovery or a map is active), log it under
     * RETRO5_ICON_DUMP with the widget name/hint so hashes can be mapped to files by eye, and consult
     * the hash->file map. A hit would give a replacement pixmap; a miss (or no map) keeps WP's own. */
    r5_icon_map_load();
    if (r5_icon_dump || r5_icon_map_n > 0) {
        uint32_t hash = r5_pixmap_hash(dpy, pm, pw, ph, pdep);
        /* Emit a config-skeleton line the first time each distinct hash is seen: "<hash> - <hint>".
         * The '-' is the blank filename (nothing mapped yet); the hint is WP's button name. Redirect
         * these into a file and set RETRO5_ICONS to it, then replace '-' with an icon path per row. */
        if (r5_icon_dump && hash && r5_dump_first_time(hash)) {   /* dedup by hash, not by pixmap */
            const char *hint = r5_widget_hint(w);
            const char *nm   = r5_widget_name(w);
            const char *lbl  = (hint && hint[0]) ? hint : (nm ? nm : "?");
            char b[320]; int k = snprintf(b, sizeof b, "%08x - %s\n", hash, lbl);
            if (k > 0) write(2, b, (size_t)k);
        }
        if (r5_icon_map_n > 0) {                          /* a map is active -> try a replacement */
            double s = r5_scale();
            unsigned tw = (unsigned)(pw * s + 0.5), th = (unsigned)(ph * s + 0.5);
            if ((custom = r5_icon_render(dpy, win, dep, hash, tw, th, bg)) != 0) {
                pm = custom; pw = tw; ph = th; pdep = dep;  /* replacement: full-colour, known size */
            }
        }
    }

    sunk = (shadow_type == R5_SHADOW_IN);

    /* Draw the whole button off-screen, then blit once (see the double-buffer banner). All the X
     * primitives below target the back buffer `dst` instead of the window; nothing reaches the
     * screen until the single commit. */
    if (!r5_canvas_begin(&cv, dpy, win, ww, hh)) return 0;
    dst = cv.buf;
    r5_win_no_autoclear(dpy, win);                        /* kill the grey enter/leave clear flash */

    /* 1. face. Filling is safe here (unlike inside _XmDrawShadows) precisely because we own the
     *    order: the icon has not been drawn yet — we draw it, below, on top. */
    face = sunk ? r5_pick(dpy, dst, R5_GC_PRESS) : r5_gc_for_pixel(dpy, dst, bg);
    if (face) r5x.FillRectangle(dpy, dst, face, 0, 0, ww, hh);

    /* 2. border: a pressed button gets the inset frame; at rest a toolbar button wears none. */
    if (sunk)            r5_inset(dpy, dst, 0, 0, (int)ww, (int)hh);
    else if (!flat_at_rest) {
        GC e = r5_pick(dpy, dst, R5_GC_EDGE);
        if (e) r5_round_rect(dpy, dst, e, 0, 0, (int)ww, (int)hh);
    }

    /* 3. the icon, centered; nudged a pixel down-right while pressed, so the press is felt. A
     *    disabled button draws its icon GREYED (desaturated + faded toward the face), so inactive
     *    tools read as inactive — applies to the native pixmap and to any replacement alike. */
    px = ((int)ww - (int)pw) / 2 + (sunk ? 1 : 0);
    py = ((int)hh - (int)ph) / 2 + (sunk ? 1 : 0);
    dim = r5_insensitive(w);
    if (pdep == 1) {                                      /* bitmap: stencil in glyph colour */
        GC g = dim ? r5_gc_for_pixel(dpy, dst, r5_blend_pixel(R5_COL_GLYPH, bg, 0.5))
                   : r5_pick(dpy, dst, R5_GC_GLYPH);
        if (g) r5x.CopyPlane(dpy, pm, dst, g, 0, 0, pw, ph, px, py, 1);
    } else {                                              /* pdep == dep: full-color icon */
        GC g = r5_gc_for_pixel(dpy, dst, bg);
        if (dim && r5_blit_gray_color(dpy, pm, dst, g, pw, ph, px, py, bg)) {
            /* greyed via the image path */
        } else if (g) {
            r5x.CopyArea(dpy, pm, dst, g, 0, 0, pw, ph, px, py);
        }
    }

    r5_carve_corners(dpy, dst, w, ww, hh);                /* carve the corners into the buffer, last */
    r5_canvas_commit(&cv, 0, 0, ww, hh);                  /* present the finished button in one blit */
    return 1;
}

/* The class expose methods we take over. Each keeps its original, used only as the fallback for a
 * button we cannot paint (no pixmap: a text label, or content drawn from an expose callback).
 * Signature is Xt's XtExposeProc: (Widget, XEvent *, Region). */
static void (*r5_orig_drawnbutton_expose)(void *, XEvent *, Region);
static void (*r5_orig_pushbutton_expose)(void *, XEvent *, Region);
static void (*r5_orig_cascade_expose)(void *, XEvent *, Region);

/* ---- menu items (WIDGET path) ----
 * WP dropdown menu entries are XmPushButton / XmCascadeButton WIDGETS, each in its own ~195x23 window
 * inside the menu-pane RowColumn (which lives in an XmMenuShell). At rest such a button draws only
 * its label; our cairo XDrawString hook renders it, but Motif redraws the item more than once, so the
 * transparent antialiased glyphs stack and darken (the "bold / double-drawn" look). Because each item
 * has its OWN window we double-buffer trivially: paint into a back buffer at (0,0), redirect Motif's
 * exact label/accelerator draw into it, blit once. We also hot-track (subtle wash under the pointer,
 * never on a disabled item) and draw our own submenu chevron for cascade items.
 *
 * A DROPDOWN item is recognised by its grandparent being an XmMenuShell — which excludes the
 * horizontal menu BAR (whose RowColumn lives in the main window, not a shell); the bar is left to
 * Motif so only the pop-up panes are reskinned. */
static int (*r5_XQueryPointer)(Display *, Window, Window *, Window *, int *, int *, int *, int *, unsigned *);
static int r5_in_menu_item;

static int r5_pointer_in(Display *dpy, Window win, unsigned w, unsigned h) {
    Window rr, cc; int prx, pry, pwx, pwy; unsigned pm;
    if (!r5_XQueryPointer) *(void **)&r5_XQueryPointer = r5_realsym("XQueryPointer");
    if (!r5_XQueryPointer) return 0;
    if (!r5_XQueryPointer(dpy, win, &rr, &cc, &prx, &pry, &pwx, &pwy, &pm)) return 0;
    return pwx >= 0 && pwx < (int)w && pwy >= 0 && pwy < (int)h;
}
static int r5_is_dropdown_item(void *w) {
    void *parent, *gp, *cls; const char *nm;
    if (!r5_XtClass) *(void **)&r5_XtClass = r5_realsym("XtClass");
    if (!r5_XtClass) return 0;
    parent = *(void **)((char *)w + 8);                  /* core.parent = the menu pane RowColumn */
    if (!parent || range_unmapped(parent, 12)) return 0;
    gp = *(void **)((char *)parent + 8);                 /* grandparent = the menu shell */
    if (!gp || range_unmapped(gp, 12)) return 0;
    cls = r5_XtClass(gp);
    if (!cls || range_unmapped((char *)cls + 8, 4)) return 0;
    nm = *(const char **)((char *)cls + 4);              /* class_name */
    if (!nm || range_unmapped((void *)nm, 8)) return 0;
    return strstr(nm, "MenuShell") != 0;
}

static int retro5_paint_menu_item(void *w, XEvent *ev, Region region, int cascade,
                                  void (*orig)(void *, XEvent *, Region)) {
    Display *dpy; Window win, root;
    int wx, wy, hot;
    unsigned ww, hh, bw, dep;
    unsigned long bg = 0xd3d3d3, fill;
    R5Canvas cv; GC face;

    if (r5_in_menu_item || !r5_skin || !w || !r5_cairo() || !r5_xlib()) return 0;
    if (!r5_is_dropdown_item(w)) return 0;               /* only pop-up panes, not the menu bar */
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return 0;
    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bw, &dep)) return 0;
    if (ww < 4 || hh < 4) return 0;
    r5_bg_pixel(w, &bg);
    r5_take_highlight(w);                                /* enter/leave -> repaint (hot-track, below) */

    hot  = !r5_insensitive(w) && r5_pointer_in(dpy, win, ww, hh);   /* highlight item under pointer */
    fill = hot ? r5_blend_pixel(0x3a6ea5u, bg, 0.24) : bg;          /* subtle blue wash */

    if (!r5_canvas_begin(&cv, dpy, win, ww, hh)) return 0;
    r5_win_no_autoclear(dpy, win);                       /* no grey flash on the hover repaint clear */
    face = r5_gc_for_pixel(dpy, cv.buf, fill);
    if (face) r5x.FillRectangle(dpy, cv.buf, face, 0, 0, ww, hh);   /* fresh face */

    r5_redir_from = win; r5_redir_to = cv.buf;           /* Motif's label/accel text -> the buffer */
    r5_in_menu_item = 1;
    if (orig) orig(w, ev, region);
    r5_in_menu_item = 0;
    r5_redir_from = 0; r5_redir_to = 0;

    if (cascade) {                                       /* our submenu chevron, replacing Motif's > */
        cairo_t *cr = r5_canvas_cairo(&cv);
        if (cr) {
            double s = hh * 0.18; if (s < 3) s = 3; if (s > 5) s = 5;
            double ax = (double)ww - hh * 0.40, ay = hh / 2.0;
            cz.set_source_rgb(cr, R5_RD(0x404040u), R5_GD(0x404040u), R5_BD(0x404040u));
            cz.move_to(cr, ax - s * 0.55, ay - s);
            cz.line_to(cr, ax + s * 0.55, ay);
            cz.line_to(cr, ax - s * 0.55, ay + s);
            cz.close_path(cr);
            cz.fill(cr);
        }
    }
    r5_canvas_commit(&cv, 0, 0, ww, hh);                 /* blit the whole item, once */
    return 1;
}

void retro5_DrawnButtonExpose(void *w, XEvent *ev, Region region) {
    if (retro5_paint_button(w, 1)) return;                /* toolbar: frameless at rest */
    if (r5_orig_drawnbutton_expose) r5_orig_drawnbutton_expose(w, ev, region);
    retro5_round_widget(w);
}
void retro5_PushButtonExpose(void *w, XEvent *ev, Region region) {
    if (retro5_paint_menu_item(w, ev, region, 0, r5_orig_pushbutton_expose)) return;  /* dropdown item */
    if (retro5_paint_button(w, 0)) return;                /* dialog buttons keep their frame */
    if (r5_orig_pushbutton_expose) r5_orig_pushbutton_expose(w, ev, region);
    retro5_round_widget(w);
}
/* XmCascadeButton — submenu entries in a pop-up pane (own our chevron); the menu BAR and option
 * menus fall through to Motif unchanged (paint_menu_item declines when not under a MenuShell). */
void retro5_CascadeButtonExpose(void *w, XEvent *ev, Region region) {
    if (retro5_paint_menu_item(w, ev, region, 1, r5_orig_cascade_expose)) return;
    if (r5_orig_cascade_expose) r5_orig_cascade_expose(w, ev, region);
}

/* ---- bigger icon toolbar buttons under the UI scale ----
 * An XmDrawnButton with a pixmap sizes itself in Motif's XmLabel SetSize: core = TextRect(pixmap) +
 * margins + 2*(marginW + shadow + highlight), but ONLY when core.width is still 0 (initial sizing).
 * We inflate the icon slot (label.TextRect) by the UI scale BEFORE SetSize runs — it then computes
 * core = round(icon*scale) + the constant chrome, and re-centers, with no reimplementation. The
 * core.width==0 gate makes it a one-shot per widget (later resizes keep the already-inflated slot).
 * Instance-field offsets verified for this build: core.width +0x20, TextRect.width +0xf4,
 * TextRect.height +0xf6. No-op at scale 1.0.
 *
 * We take this over by jmp-patching the resize THUNK at 0x086bae18, NOT the class-record slot: the
 * slot is an INHERITED method that Xt re-resolves at first widget creation, silently clobbering any
 * load-time slot swap (see MOTIF-DRAW-TAKEOVER-PLAN.md / memory). Patching the function entry is
 * immune to that. The thunk is a two-line trampoline whose whole body is `SetSize(w, 5)` (push $5;
 * push widget; call 0x086baea4) — we reproduce it by calling that worker directly after inflating.
 * The thunk is shared by XmDrawnButton AND XmPushButton, so we gate the inflate to the DrawnButton
 * class (toolbar icons); dialog PushButtons pass straight through and are never double-scaled (their
 * text already scales via the font metrics). No-op at scale 1.0, so stock-dpi displays are untouched.
 *
 * NB: XCopyArea does not scale, so this enlarges the BUTTON (icon centered with more padding); the
 * icon glyph itself only grows via a larger source pixmap (the planned SVG-by-hash replacement). */
#define R5_RESIZE_OFF (R5_EXPOSE_OFF - 4)                /* offsetof(CoreClassPart, resize) = 64 */
#define R5_DRAWNBUTTON_CLASS 0x087cd050                  /* XmDrawnButtonClassRec */
static void (*r5_label_setsize)(void *, int) = (void (*)(void *, int))0x086baea4;  /* the resize worker */

void retro5_DrawnButtonResize(void *w) {
    if (r5_skin && w) {
        if (!r5_XtClass) *(void **)&r5_XtClass = r5_realsym("XtClass");
        if (r5_XtClass && r5_XtClass(w) == (void *)R5_DRAWNBUTTON_CLASS) {  /* toolbar icons only */
            double s = r5_scale();
            unsigned short *cw = (unsigned short *)((char *)w + 0x20);   /* core.width */
            if (s > 1.0001 && *cw == 0) {                /* initial sizing only -> inflate icon slot */
                unsigned short *tw = (unsigned short *)((char *)w + 0xf4);   /* label.TextRect.width  */
                unsigned short *th = (unsigned short *)((char *)w + 0xf6);   /* label.TextRect.height */
                if (*tw && *tw < 2000) *tw = (unsigned short)(*tw * s + 0.5);
                if (*th && *th < 2000) *th = (unsigned short)(*th * s + 0.5);
            }
        }
    }
    r5_label_setsize(w, 5);                              /* the thunk's body: SetSize(w, 5) */
}

/* ============================================================================================ *
 *  Document canvas font rendering — anti-aliased glyphs in the page (env RETRO5_DOCFONT)
 * ============================================================================================ *
 * WP renders document text with its OWN Type1 engine, not XDrawString: draw_text_run (0x085b54e0)
 * walks the char buffer, and for each char with a glyph it blits WP's 1-bit rasterised glyph pixmap
 * (glyphTable[c*12] -> +0x18) via XCopyPlane (plane 1) at 0x085b5916. So the crisp UI text hook does
 * NOT reach the canvas; the page stays 1-bit/aliased.
 *
 * To render the SAME text with cairo (anti-aliased) WITHOUT reimplementing WP's layout, we let
 * draw_text_run run unchanged (it computes every glyph's device box + advance + newlines, so line
 * breaks/justification are byte-identical) and intercept each glyph's XCopyPlane, drawing the known
 * char with cairo instead of blitting the bitmap. The catch: chars with no glyph (space: pixmap==0)
 * are skipped by WP's blit loop, so the i-th XCopyPlane != buf[i]. We resolve it by pre-filtering the
 * buffer through the SAME pixmap!=0 test WP uses, so the i-th blit maps to the i-th filtered char.
 *
 * OPT-IN and safe: without RETRO5_DOCFONT we never patch draw_text_run or hook XCopyPlane — the page
 * is byte-for-byte WP's own. Any failure (no cairo, bad glyph table) falls back to WP's bitmap blit. */
static int r5_docfont;                                   /* RETRO5_DOCFONT: cairo-render the canvas */
static int r5_docfont81;                                 /* RETRO5_DOCFONT81: EXPERIMENTAL 8.1 canvas */
static int r5_allfonts;                                  /* RETRO5_ALLFONTS: unfilter the font selector */
static int r5_fontcoll;                                  /* RETRO5_FONTCOLL: append system faces to the
                                                          * printer-font COLLECTION that every font picker
                                                          * (F9 + toolbar combos) enumerates from. This is
                                                          * what makes injected fonts actually LIST + select.
                                                          * Defaults to ALLFONTS (set 0 to opt out). See
                                                          * r5_install_collection_injection — LIVE-VERIFIED
                                                          * working + teardown-safe (2026-07-13). */

/* Per-build symbol/address table. Filled once at load time by the detected build's takeover
 * (takeoverWP80 / takeoverWP81) so the rest of the code carries NO per-build #ifdefs — every doc-font
 * function and the selector patch read r5s.<field>. 8.1 differs from 8.0 in relocated globals and in
 * STATIC-linked Xlib (XCopyPlane is a static fn with no GOT), hence both a GOT-interpose path (8.0)
 * and a call-site path (8.1). See installer/wp81port/FONT-RENDERING-MAP.md §14.
 * The R5Syms shape now lives in r5syms.h (shared with takeover81.c); `r5s` is the one instance and is
 * NON-static so the 8.1 wheel module can reach it. */
R5Syms r5s;

/* --- printertocups bridge (RETRO5_CUPS) ---------------------------------------------------------
 * retro5 deep-loads printertocups.so (RTLD_DEEPBIND, like cairo/librsvg) so libcups' modern glibc/
 * gnutls deps never collide with WP's libc5 shim. The interface is async + thread-safe: p2c_submit
 * queues and returns, and p2c_enum serves a prefetched cache — nothing here blocks WP's UI thread,
 * exactly as the old print IPC returned before spooling. Loaded once when CUPS mode is on; on load
 * we p2c_init (starts the worker) and p2c_prefetch (warms the destination cache in the background),
 * so the Select-Printer dialog is instant. */
static int r5_cups;                               /* RETRO5_CUPS: back WP's printer subsystem with CUPS */
/* R5P2CPrinter (== P2CPrinter) is defined in r5syms.h, included above. */
static struct {
    int   ready;
    void *h;
    int   (*init)(void);
    int   (*prefetch)(void);
    int   (*enumerate)(R5P2CPrinter *, int);
    long  (*submit)(const char *, const char *, const char *, const void *, size_t, const void *, int);
    int   (*wait_idle)(int);                      /* block until the worker has handed all jobs to CUPS */
    void  (*shutdown)(void);
} r5p2c;

static int r5_p2c_load(void) {
    void *h;
    if (r5p2c.ready) return 1;
    if (!(h = dlopen("printertocups.so", RTLD_NOW | RTLD_DEEPBIND))) return 0;
    *(void **)&r5p2c.init      = dlsym(h, "p2c_init");
    *(void **)&r5p2c.prefetch  = dlsym(h, "p2c_prefetch");
    *(void **)&r5p2c.enumerate = dlsym(h, "p2c_enum");
    *(void **)&r5p2c.submit    = dlsym(h, "p2c_submit");
    *(void **)&r5p2c.wait_idle = dlsym(h, "p2c_wait_idle");
    *(void **)&r5p2c.shutdown  = dlsym(h, "p2c_shutdown");
    if (!r5p2c.init || !r5p2c.enumerate || !r5p2c.submit) return 0;
    r5p2c.h = h;
    r5p2c.ready = 1;
    if (r5p2c.init() == 0 && r5p2c.prefetch) r5p2c.prefetch();   /* worker up + dest cache warming */
    if (r5_trace) { const char *m = "retro5: printertocups loaded (CUPS backend ready)\n";
                    write(2, m, strlen(m)); }
    return 1;
}

/* CUPS job routing (RETRO5_CUPS) is implemented at the wppx PostScript-write stage — retro5's own
 * libc file-I/O layer captures the `%!PS-Adobe` bytes as the spooler writes /tmp/_pp_<pid> and hands
 * the buffer to printertocups (p2c_submit), suppressing the legacy `lpr`. See the file-I/O interpose.
 * (The old wpexc-spawn bypass was removed: §20 proved wpexc is an idle daemon off the print path, so
 * bypassing it only caused the "Cannot create a new process" spawn-loop.) */

/* Is CUPS routing on? Exported so retro5's libc file-I/O layer (forward.c) can gate its capture of
 * the spooler's PostScript and its suppression of the real `lpr` without duplicating the env parse. */
int r5_cups_enabled(void) { return r5_cups; }

/* RETRO5_PRINT_PDF: convert the captured PostScript to a font-embedded PDF (via Ghostscript) before
 * spooling to CUPS. Default ON when CUPS routing is on; only an explicit "0" turns it off. Cached. */
static int r5_print_pdf_enabled(void) {
    static int v = -1;
    if (v == -1) { const char *e = getenv("RETRO5_PRINT_PDF"); v = (e && e[0] == '0' && e[1] == 0) ? 0 : 1; }
    return v;
}

extern int fork(void);
extern int execv(const char *, char *const *);
extern int waitpid(int, int *, int);
extern void _exit(int);
extern int unlink(const char *);

/* Convert captured PostScript (ps/len) to a PDF with every font embedded, using Ghostscript.
 *
 * CRITICAL ordering: this runs in wppx BEFORE r5_p2c_load() starts any printertocups worker thread,
 * so the fork+exec below happens while this process is still single-threaded — no libcups/glibc lock
 * can be held across the fork, so gs cannot deadlock the child. (Forking AFTER the workers exist is
 * the documented hazard; hence the caller invokes us first.)
 *
 * Returns a malloc'd PDF buffer (caller frees) with *outlen set, or NULL on ANY failure (gs missing,
 * nonzero/failed run, or output that is not a real PDF) so the caller falls back to spooling the raw
 * PS and never loses the job. The intermediate /tmp/r5_out_<pid>.pdf is KEPT under RETRO5_TRACE for
 * inspection; otherwise both temps are unlinked before we return.
 *
 * Font handling (see STEP 1 findings): WP's spooler does NOT reference user fonts by name for the
 * interpreter to supply — it rasterises each glyph itself into an inline Type 3 bitmap font and only
 * the base-14 faces (Courier/Helvetica/Times) travel as named NeededFonts. So EmbedAllFonts makes the
 * PDF fully self-contained, and -sFONTPATH lets gs resolve those base-14 names to system TTFs where
 * possible; the user's picked face is preserved by NAME + as baked bitmaps, not as scalable outlines
 * (recovering true TTF outlines would require overriding wppx's font emission — out of scope here). */
static void *r5_ps_to_pdf(const void *ps, unsigned len, unsigned *outlen) {
    char inps[64], outpdf[64], ofarg[96];
    int pid = (int)getpid(), child, status = 0;
    FILE *f;
    unsigned char *pdf; size_t plen = 0;

    *outlen = 0;
    snprintf(inps,   sizeof inps,   "/tmp/r5_in_%d.ps",   pid);
    snprintf(outpdf, sizeof outpdf, "/tmp/r5_out_%d.pdf",  pid);
    snprintf(ofarg,  sizeof ofarg,  "-sOutputFile=%s",     outpdf);

    /* 1. spill the in-memory PS to a temp file gs can read */
    if (!(f = fopen(inps, "wb"))) return 0;
    if (fwrite(ps, 1, len, f) != len) { fclose(f); unlink(inps); return 0; }
    fclose(f);

    /* 2. fork+exec gs (quiet; on success it writes only to the -sOutputFile, nothing to stdout, and
     *    any error text on stderr lands in the trace log). */
    child = fork();
    if (child < 0) { unlink(inps); return 0; }
    if (child == 0) {
        char *argv[] = {
            (char *)"/usr/bin/gs", (char *)"-q", (char *)"-dBATCH", (char *)"-dNOPAUSE",
            (char *)"-dSAFER", (char *)"-sDEVICE=pdfwrite",
            (char *)"-dEmbedAllFonts=true", (char *)"-dSubsetFonts=true",
            (char *)"-dCompatibilityLevel=1.4", (char *)"-sFONTPATH=/usr/share/fonts",
            ofarg, inps, 0
        };
        execv("/usr/bin/gs", argv);
        _exit(127);                                   /* gs not found -> caller falls back to PS */
    }
    if (waitpid(child, &status, 0) < 0) { unlink(inps); unlink(outpdf); return 0; }
    unlink(inps);                                     /* input temp no longer needed */

    /* 3. read the PDF back; success == a non-empty file whose header is really "%PDF-". */
    pdf = r5_read_file(outpdf, &plen);
    if (!r5_trace) unlink(outpdf);                    /* keep under trace, else drop */
    if (!pdf) return 0;
    if (plen < 5 || pdf[0] != '%' || pdf[1] != 'P' || pdf[2] != 'D' || pdf[3] != 'F' || pdf[4] != '-') {
        free(pdf);
        return 0;                                     /* gs produced garbage/empty -> fall back to PS */
    }
    *outlen = (unsigned)plen;
    return pdf;
}

/* Route ONE finished print job to CUPS instead of the legacy `lpr`. Called from the system()/execvp()
 * interpose in forward.c the moment wppx tries to spool `/tmp/_pp_<pid>_1` to <dest>. `ps`/`len` is
 * the captured `%!PS-Adobe` body. Returns 1 if we handled it (caller MUST then suppress the real lpr),
 * 0 if CUPS is off or the backend could not be loaded (caller runs the real lpr — graceful degrade).
 *
 * SYNCHRONOUS by necessity: wppx exits immediately after system() returns, so an un-drained async
 * submit would be lost with the process. We submit then p2c_wait_idle() (worker hands the job to CUPS
 * before we return); if the bridge lacks wait_idle we fall back to shutdown(), which also drains. */
int r5_cups_spool(const char *dest, const void *ps, unsigned len) {
    long job;
    const void *body = ps;                        /* what we actually submit... */
    unsigned     blen = len;
    const char  *fmt  = "application/postscript";  /* ...and its MIME type (PS by default) */
    void        *pdf  = 0;
    unsigned     pdflen = 0;
    if (!r5_cups) return 0;                        /* gate off -> caller runs the real lpr */

    /* PS -> font-embedded PDF, done HERE (before r5_p2c_load spins up worker threads, so the gs
     * fork+exec is deadlock-free — see r5_ps_to_pdf). On any failure we keep the original PS. */
    if (r5_print_pdf_enabled()) {
        pdf = r5_ps_to_pdf(ps, len, &pdflen);
        if (pdf) { body = pdf; blen = pdflen; fmt = "application/pdf"; }
        if (r5_trace) {
            char b[220]; int n = snprintf(b, sizeof b,
                "retro5: print PS %u bytes -> PDF %u bytes (gs), embedded=%s -> submit as %s\n",
                len, pdflen, pdf ? "yes" : "no (gs failed; PS fallback)", fmt);
            if (n > 0) write(2, b, (size_t)n);
        }
    }

    if (!r5_p2c_load()) { if (pdf) free(pdf); return 0; }  /* backend gone -> fall back to lpr */
    job = r5p2c.submit((dest && *dest) ? dest : 0, "WordPerfect", fmt, body, (size_t)blen, 0, 0);
    if (r5p2c.wait_idle) r5p2c.wait_idle(-1);     /* drain before wppx exits */
    else                 r5p2c.shutdown();        /* older bridge: shutdown() also drains + joins */
    if (r5_trace) {
        char b[160]; int n = snprintf(b, sizeof b,
            "retro5: p2c_submit dest=%s fmt=%s len=%u job=%ld (drained)\n",
            (dest && *dest) ? dest : "(default)", fmt, blen, job);
        if (n > 0) write(2, b, (size_t)n);
    }
    if (pdf) free(pdf);
    return 1;                                     /* handled: suppress the legacy lpr */
}

static void (*r5_doc_text_orig)(void *, int, int, int, int, int);  /* trampoline to the real body */
static int r5_doc_active;                                /* set only during our draw_text_run call */
static double r5_doc_px;                                 /* RETRO5_DOCFONT_PX size override (0 = auto) */
static char r5_cur_family[80];                           /* Phase 3: current run's injected family, or "" */
static double r5_run_size;                               /* chrome runs (DOCFONT=2): one size per run */
/* Reverse map: WP rasterises glyphs LAZILY (pixmap at glyphTable[c*12]->+0x18 is 0 until first draw),
 * so pre-filtering the buffer by pixmap!=0 dropped not-yet-rendered chars and desynced the mapping.
 * At BLIT time the pixmap IS populated and uniquely identifies the char, so recover the char from the
 * XCopyPlane source pixmap by scanning the (now-live) glyph table. Cached by pixmap. */
static struct { unsigned pm; unsigned char c; } r5_pmc[256];
static int r5_pmc_n;
static unsigned char r5_pixmap_to_char(unsigned pm) {
    int i; unsigned tab;
    if (!pm || !r5s.glyphtab_get) return 0;
    for (i = 0; i < r5_pmc_n; i++) if (r5_pmc[i].pm == pm) return r5_pmc[i].c;
    tab = r5s.glyphtab_get();
    if (!tab || range_unmapped((void *)(uintptr_t)tab, 12)) return 0;
    for (i = 1; i < 256; i++) {
        unsigned entry = tab + (unsigned)i * 12, glyph, gpm = 0;
        if (range_unmapped((void *)(uintptr_t)entry, 4)) continue;
        glyph = *(unsigned *)(uintptr_t)entry;
        if (glyph && !range_unmapped((void *)(uintptr_t)(glyph + 0x18), 4))
            gpm = *(unsigned *)(uintptr_t)(glyph + 0x18);
        if (gpm && gpm == pm) {
            if (r5_pmc_n < 256) { r5_pmc[r5_pmc_n].pm = pm; r5_pmc[r5_pmc_n].c = (unsigned char)i; r5_pmc_n++; }
            return (unsigned char)i;
        }
    }
    return 0;
}

/* Build a callable trampoline for a jmp-patched function: copy `keep` prologue bytes (whole
 * instructions, >=5, position-independent) to fresh RWX memory + a jmp back to va+keep. */
void *r5_make_trampoline(uintptr_t va, unsigned keep) {   /* non-static: takeover81.c */
    long pg = sysconf(_SC_PAGESIZE); if (pg <= 0) pg = 4096;
    unsigned char *tr = (unsigned char *)mmap(0, (size_t)pg, PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int32_t rel;
    if (tr == MAP_FAILED) return 0;
    memcpy(tr, (void *)va, keep);
    tr[keep] = 0xe9;
    rel = (int32_t)((va + keep) - ((uintptr_t)tr + keep + 5));
    memcpy(tr + keep + 1, &rel, 4);
    return tr;
}

/* ---- document face matching --------------------------------------------------------------------
 * The current font's identity lives in a WP font record (+0x10 = .pfb path / WP face name). At the
 * blit site draw_text_run has only the glyph table (= some record's +0x18), not the record, so we
 * reverse-scan the font-record pointer array for the record whose +0x18 == the current glyph table
 * and read its +0x10. That face string maps to a fontconfig generic (Serif/Sans/Monospace) so the
 * SYSTEM font engine supplies the real face; slant/weight are derived from the name. Cached by the
 * glyph-table value (the "current font" changes only when WP switches face/size/attr). */
/* Constant device-pixel size for the whole run, from the font context at [0x08808798] (8.0) /
 * [0x08828204] (8.1). The context has TWO relevant words:
 *   +0x00 high word = selected POINT SIZE * 50 (the scaled size — this is what tracks 12/25/46 pt).
 *          Confirmed live on 8.0: 12pt->600, 25pt->1250, 46pt->2300 (exactly ptsize*50). WP's own
 *          metric provider (font_metric_provider, width*ptsize/3600) draws its bitmap and advances
 *          from THIS, so sizing cairo by it makes the glyph match WP's ink box + pen advance.
 *   +0x04 high word = a fixed device marker (==16 for document runs; 0 for the status-bar / chrome
 *          runs the same engine draws). We use it ONLY to tell doc runs from chrome — it does NOT
 *          scale with point size, which is why the old code (which SIZED by it) drew every size at
 *          the 12pt raster: tiny glyphs, correct spacing.
 * device px = (+0x00 hi) / 37.5  ==  ptsize * 96/72  (96 dpi). Anchored so 12pt (600) -> 16 px,
 * matching the previously-confirmed 12pt calibration exactly; 46pt -> 61.3 px, etc.
 * Returns 0 when there is NO reliable run size (chrome: +0x04 hi not a doc marker) so the caller
 * falls back to WP's own 1-bit blit / the DOCFONT=2 ink-box lock. RETRO5_DOCFONT_PX overrides. */
static double r5_doc_pixsize(void) {
    unsigned ctx, marker; double px;
    if (r5_doc_px > 0) return r5_doc_px;
    if (r5s.font_ctx && !range_unmapped((void *)r5s.font_ctx, 4)) {
        ctx = *(unsigned *)r5s.font_ctx;
        if (ctx && !range_unmapped((void *)(uintptr_t)ctx, 8)) {
            marker = (*(unsigned *)(uintptr_t)(ctx + 4)) >> 16;         /* doc-run marker (16); 0=chrome */
            if (marker >= 4 && marker <= 400) {                        /* a real document run */
                px = (double)((*(unsigned *)(uintptr_t)ctx) >> 16) / 37.5;  /* ptsize*50 -> device px */
                if (px >= 4 && px <= 400) return px;
            }
        }
    }
    return 0.0;                                          /* no doc run size -> let WP draw it */
}

/* Map a WP face name -> cairo family, deriving slant/weight from style suffixes. Also sets *symbolic
 * for faces cairo cannot render from a raw WP byte: symbol/pi/dingbat fonts and non-Latin scripts use
 * a font-specific encoding, so feeding cairo the byte as Latin would draw the wrong glyph (the "N"
 * bug). Those pass through to WP's native blit until we build per-encoding->Unicode maps. */
static const char *r5_face_to_family(const char *face, int *slant, int *weight, int *symbolic) {
    char b[128]; int n = 0; const char *p, *base;
    *slant = CAIRO_FONT_SLANT_NORMAL; *weight = CAIRO_FONT_WEIGHT_NORMAL; *symbolic = 0;
    if (!face || !*face) return "Serif";
    for (base = face, p = face; *p; p++) if (*p == '/' || *p == '\\') base = p + 1;   /* basename */
    for (n = 0; base[n] && n < (int)sizeof b - 1; n++)
        b[n] = (base[n] >= 'A' && base[n] <= 'Z') ? base[n] + 32 : base[n];
    b[n] = 0;
    /* Symbol / pi / dingbat / iconic + non-Latin scripts: cairo-from-byte is wrong -> passthrough. */
    if (strstr(b,"symbol")||strstr(b,"dingbat")||strstr(b,"iconic")||strstr(b,"wingding")
        ||strstr(b,"webding")||strstr(b,"boxdraw")||strstr(b,"phonetic")||strstr(b,"mathext")
        ||strstr(b,"wpmath")||strstr(b,"wpicon")||strstr(b,"zapf")||strstr(b,"wpmex")
        ||strstr(b,"greek")||strstr(b,"cyrillic")||strstr(b,"hebrew")||strstr(b,"arabic")
        ||strstr(b,"japan")||strstr(b,"hiragana")||strstr(b,"katakana")||strstr(b,"hangul")
        ||strstr(b,"thai")||strstr(b,"sihafa")) {
        *symbolic = 1;
        return "Serif";                                  /* family unused; caller passes through */
    }
    if (strstr(b,"italic") || strstr(b,"oblique")) *slant = CAIRO_FONT_SLANT_ITALIC;
    if (strstr(b,"bold") || strstr(b,"demi") || strstr(b,"black") || strstr(b,"heavy"))
        *weight = CAIRO_FONT_WEIGHT_BOLD;
    if (strstr(b,"courier")||strstr(b,"mono")||strstr(b,"cour")||strstr(b,"wpcr")||strstr(b,"wpco"))
        return "Monospace";
    if (strstr(b,"helv")||strstr(b,"arial")||strstr(b,"swiss")||strstr(b,"univers")||strstr(b,"wphv")
        ||strstr(b,"sans")||strstr(b,"gothic"))
        return "Sans";
    /* Times / CG Times / Dutch / Roman / most serif book faces (and the safe document default). */
    return "Serif";
}

/* Current document face name. The current-font metric struct pointer lives at [0x0880878c]; its
 * +0x00 is a char* to the PostScript face name (e.g. "Courier10PitchBT-Roman", "Dutch801BT-Bold").
 * Two derefs, fully range-guarded — no scanning. (Cross-checked live: the active record's +0x18 also
 * equals this metric pointer, and its +0x10 is the friendly name, but +0x00 here carries the style
 * suffix we want for slant/weight.) Returns NULL if anything is unmapped -> caller uses a generic. */
static const char *r5_doc_face(void) {
    unsigned met, name;
    if (!r5s.metric_ptr || range_unmapped((void *)r5s.metric_ptr, 4)) return 0;
    met = *(unsigned *)r5s.metric_ptr;
    if (!met || range_unmapped((void *)(uintptr_t)met, 4)) return 0;
    name = *(unsigned *)(uintptr_t)met;                        /* metric struct +0x00 = face char* */
    if (!name || range_unmapped((void *)(uintptr_t)name, 1)) return 0;
    return (const char *)(uintptr_t)name;
}

/* Family + slant/weight for the current document run, cached by the metric-struct pointer (which
 * changes on every face/size/attribute switch). */
static struct { unsigned key; char fam[64]; int slant, weight, symbolic; int has; } r5_doc_facecache;
static const char *r5_doc_family(int *slant, int *weight, int *symbolic) {
    unsigned key = (!r5s.metric_ptr || range_unmapped((void *)r5s.metric_ptr, 4))
                 ? 0 : *(unsigned *)r5s.metric_ptr;
    const char *face, *fam;
    /* The resolver hook captured the SELECTED font's record name (WP may substitute its metric to a
     * stock face, so the metric name is unreliable for display/injected fonts). Render from the record
     * name: a real fontconfig family (DejaVu Sans, Inter Display, Courier, Times...) is used VERBATIM
     * so fontconfig resolves the true face; a WP-stock name (…-WP, "WP …") maps to a generic and takes
     * its slant/weight from the metric PS name (which carries -Bold/-Italic). */
    if (r5_cur_family[0]) {
        int s = 0, w = 0, sym = 0;
        const char *b = r5_cur_family, *p;
        int wpstock = 0;
        for (p = b; p[0] && p[1]; p++) if (p[0]=='-' && (p[1]=='W'||p[1]=='w') && (p[2]=='P'||p[2]=='p')) wpstock = 1;
        if ((b[0]=='W'||b[0]=='w') && (b[1]=='P'||b[1]=='p') && b[2]==' ') wpstock = 1;   /* "WP …" */
        r5_face_to_family(b, &s, &w, &sym);           /* slant/weight/symbolic from the record name  */
        *slant = s; *weight = w; *symbolic = sym;
        if (sym) return "Serif";                      /* symbolic -> caller passes through to WP      */
        if (!wpstock) return r5_cur_family;           /* real family: verbatim (fontconfig resolves)  */
        { const char *face = r5_doc_face();           /* WP stock: generic family + metric-derived style */
          const char *gen = r5_face_to_family(face && *face ? face : b, slant, weight, symbolic);
          return gen; }
    }
    if (r5_doc_facecache.has && r5_doc_facecache.key == key) {
        *slant = r5_doc_facecache.slant; *weight = r5_doc_facecache.weight;
        *symbolic = r5_doc_facecache.symbolic;
        return r5_doc_facecache.fam;
    }
    face = r5_doc_face();
    fam = r5_face_to_family(face, slant, weight, symbolic);
    if (r5_trace) {
        char m[192]; int k = snprintf(m, sizeof m, "retro5: doc face '%s' -> %s%s%s%s\n",
            face ? face : "(none)", fam, *weight ? " bold" : "", *slant ? " italic" : "",
            *symbolic ? " [symbol->native]" : "");
        if (k > 0) write(2, m, (size_t)k);
    }
    r5_doc_facecache.key = key; r5_doc_facecache.slant = *slant; r5_doc_facecache.weight = *weight;
    r5_doc_facecache.symbolic = *symbolic;
    strncpy(r5_doc_facecache.fam, fam, sizeof r5_doc_facecache.fam - 1);
    r5_doc_facecache.fam[sizeof r5_doc_facecache.fam - 1] = 0; r5_doc_facecache.has = 1;
    return r5_doc_facecache.fam;
}

/* Extract one channel from an X pixel value given its visual mask (handles any TrueColor depth). */
static double r5_chan(unsigned long px, unsigned long mask) {
    unsigned long m = mask, v; int shift = 0, bits = 0;
    if (!m) return 0.0;
    while (!(m & 1)) { m >>= 1; shift++; }
    while (m & 1)    { m >>= 1; bits++; }
    v = (px & mask) >> shift;
    return bits ? (double)v / (double)((1UL << bits) - 1) : 0.0;
}
/* WP carries the text COLOUR in the GC foreground used for the glyph blit (the 1-bit plane is drawn
 * in that colour). Read it and map the pixel through the canvas visual so coloured text renders in
 * its real colour instead of always black. Falls back to black if the GC value isn't cached. */
static int (*r5_XGetGCValues)(Display *, GC, unsigned long, XGCValues *);
static void r5_doc_text_color(Display *dpy, GC gc, double *r, double *g, double *b) {
    XGCValues gv; Visual *v = DefaultVisual(dpy, DefaultScreen(dpy));
    *r = *g = *b = 0.0;                                   /* default black */
    if (!gc || !v) return;
    if (!r5_XGetGCValues) *(void **)&r5_XGetGCValues = r5_realsym("XGetGCValues");
    if (!r5_XGetGCValues || !r5_XGetGCValues(dpy, gc, GCForeground, &gv)) return;
    if (!v->red_mask || !v->green_mask || !v->blue_mask) return;   /* non-TrueColor -> keep black */
    *r = r5_chan(gv.foreground, v->red_mask);
    *g = r5_chan(gv.foreground, v->green_mask);
    *b = r5_chan(gv.foreground, v->blue_mask);
}

/* WP byte -> Unicode codepoint. WP's Latin text fonts are encoded ISO 8859-1 (Latin-1), where the
 * codepoint IS the byte value (0x00-0xFF), so the default table is the identity; this is a table
 * (not a formula) so a font/charset that turns out NOT to be 8859-1 can be remapped in one place.
 * cairo's show_text wants UTF-8, so a raw high byte (>=0x80) must be encoded as 2 bytes — emitting it
 * bare (as we did) is invalid UTF-8 and drew tofu for accented characters. */
static unsigned short r5_wp2uni[256];
static int r5_wp2uni_ready;
static void r5_wp2uni_init(void) {
    int i;
    for (i = 0; i < 256; i++) r5_wp2uni[i] = (unsigned short)i;   /* ISO 8859-1: codepoint == byte */
    r5_wp2uni_ready = 1;
}
static int r5_utf8(unsigned cp, char *o) {                       /* encode cp -> UTF-8, return length */
    if (cp < 0x80)   { o[0] = (char)cp; return 1; }
    if (cp < 0x800)  { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    o[2] = (char)(0x80 | (cp & 0x3F)); return 3;
}

/* Render one char with cairo where WP's XCopyPlane would have blitted its 1-bit glyph. WP has just
 * set the device pen for this glyph in the globals: origin x = [R5_PEN_X], baseline y = [R5_PEN_Y]
 * (dst_x/dst_y in the blit are the ink box, offset by the glyph's bearings — using the pen origin +
 * baseline is exact for cairo's show_text). Size is one run-consistent value (the per-glyph ink box
 * height varies, so we do NOT size by it): RETRO5_DOCFONT_PX overrides; else a heuristic from the box
 * height (a rough cap-height -> em). Face is matched from the current font record's .pfb (+0x10);
 * colour comes from the blit GC's foreground. */
static int r5_doc_render_glyph(Display *dpy, Drawable dst, GC gc, unsigned w, unsigned h, unsigned char c) {
    cairo_surface_t *sf; cairo_t *cr; char s[5]; int slant, weight, symbolic; double cr_, cg, cb;
    const char *fam = r5_doc_family(&slant, &weight, &symbolic);
    int penx = *(int *)r5s.pen_x, peny = *(int *)r5s.pen_y;
    double sz = r5_doc_pixsize();
    if (symbolic) return 0;                               /* symbol/pi/non-Latin -> WP's native glyph */
    if (sz <= 0) {
        /* No font-context run size => UI chrome drawn by the same engine (status bar, F9 preview).
         * RETRO5_DOCFONT=2 renders those with cairo too; use ONE size per run (locked from the first
         * glyph) so the whole run is consistent — that avoids the per-glyph size wobble. Level 1
         * leaves chrome to WP's native 1-bit blit. */
        if (r5_docfont < 2) return 0;
        if (r5_run_size > 0) sz = r5_run_size;
        else { sz = (double)h * 1.35; r5_run_size = sz; }
    }
    if (!cz.icons_ok || c < 32 || w < 1 || h < 1 || w > 400 || h > 400) return 0;
    if (penx < 0 || peny < 0 || penx > 20000 || peny > 20000) return 0;   /* sanity */
    sf = cz.xlib_surface_create(dpy, dst, DefaultVisual(dpy, DefaultScreen(dpy)), penx + 64, peny + 24);
    if (!sf || cz.surface_status(sf)) { if (sf) cz.surface_destroy(sf); return 0; }
    cr = cz.create(sf);
    if (!cr || cz.status(cr)) { if (cr) cz.destroy(cr); cz.surface_destroy(sf); return 0; }
    if (!r5_wp2uni_ready) r5_wp2uni_init();
    s[r5_utf8(r5_wp2uni[c], s)] = 0;                     /* WP byte -> Unicode -> UTF-8 for cairo */
    r5_doc_text_color(dpy, gc, &cr_, &cg, &cb);
    cz.select_font_face(cr, fam, slant, weight);
    cz.set_font_size(cr, sz);
    cz.set_source_rgb(cr, cr_, cg, cb);
    cz.move_to(cr, (double)penx, (double)peny);          /* pen origin x, baseline y */
    cz.show_text(cr, s);
    cz.surface_flush(sf);
    cz.destroy(cr);
    cz.surface_destroy(sf);
    return 1;
}

/* XCopyPlane — redirect-aware for the canvas. During a doc_text run we recover the char from the
 * source glyph pixmap and cairo-render it; otherwise a plain passthrough (WP uses XCopyPlane widely). */
static int (*r5_real_CopyPlane_x)(Display *, Drawable, Drawable, GC, int, int, unsigned, unsigned, int, int, unsigned long);
void retro5_XCopyPlane(Display *dpy, Drawable src, Drawable dst, GC gc,
                       int sx, int sy, unsigned w, unsigned h, int dx, int dy, unsigned long plane) {
    if (r5_doc_active) {
        unsigned char c = r5_pixmap_to_char((unsigned)src);       /* recover char from glyph pixmap */
        if (c && r5_doc_render_glyph(dpy, dst, gc, w, h, c)) return; /* rendered via cairo */
    }
    if (!r5_real_CopyPlane_x) {
        if (r5s.xcp_fn) *(void **)&r5_real_CopyPlane_x = (void *)r5s.xcp_fn;  /* 8.1: static X fn */
        else *(void **)&r5_real_CopyPlane_x = r5_realsym("XCopyPlane");        /* 8.0: dynamic */
    }
    if (r5_real_CopyPlane_x) r5_real_CopyPlane_x(dpy, src, dst, gc, sx, sy, w, h, dx, dy, plane);
}

/* draw_text_run takeover: just flag the run and let WP's own body compute every glyph position/advance
 * and issue the XCopyPlane blits; our hook turns each into a cairo glyph. No pre-filtering (the lazy
 * rasterisation made that unreliable) — the char is recovered from the pixmap at blit time. */
void retro5_doc_text(void *buf, int count, int px, int py, int flag, int mode) {
    if (!r5_docfont || !r5_cairo() || !cz.icons_ok || !r5_doc_text_orig) {
        if (r5_doc_text_orig) r5_doc_text_orig(buf, count, px, py, flag, mode);
        return;
    }
    r5_doc_active = 1;
    r5_run_size = 0;                                     /* new run: re-lock the chrome size (DOCFONT=2) */
    r5_doc_text_orig(buf, count, px, py, flag, mode);
    r5_doc_active = 0;
}

/* True when a widget is insensitive (disabled). XtIsSensitive is the correct test — it folds in
 * ancestor sensitivity — and is a genuine libXt symbol, unlike the XmNsensitive resource read which
 * proved unreliable here. Resolved directly from libXt (never RTLD_DEFAULT). */
static int (*r5_XtIsSensitive)(void *);
static int r5_insensitive(void *w) {
    if (!r5_XtIsSensitive) *(void **)&r5_XtIsSensitive = r5_realsym("XtIsSensitive");
    return r5_XtIsSensitive ? !r5_XtIsSensitive(w) : 0;  /* unknown -> treat as sensitive */
}

/* Set a cairo source from a 0xRRGGBB constant, blended halfway to `bg` when `dim` — the same 50%
 * fade Motif's insensitive text uses, so a disabled toggle's indicator greys with its label. */
static void r5_ind_col(cairo_t *cr, uint32_t rgb, int dim, unsigned long bg) {
    double r = R5_RD(rgb), g = R5_GD(rgb), b = R5_BD(rgb);
    if (dim) { r = r * 0.5 + R5_RD(bg) * 0.5; g = g * 0.5 + R5_GD(bg) * 0.5; b = b * 0.5 + R5_BD(bg) * 0.5; }
    cz.set_source_rgb(cr, r, g, b);
}

/* Paint one radio/checkbox indicator into an existing cairo context, at cell (x,y) size sz. Shared
 * by the full toggle EXPOSE (which also draws the background + label) and by DrawToggle (the
 * arm/select/disarm redraw path, which repaints just this cell). itype: XmONE_OF_MANY=2 -> radio
 * circle, XmN_OF_MANY=1 -> checkbox square; set -> filled/accented; dim -> insensitive (greyed). bg
 * fills the cell first so a repaint erases whatever was underneath. */
static void r5_paint_indicator(cairo_t *cr, int x, int y, int sz, long itype, long set,
                               unsigned long bg, int dim) {
    double cx, cy, r;
    cz.set_source_rgb(cr, R5_RD(bg), R5_GD(bg), R5_BD(bg));
    cz.rectangle(cr, x - 1, y - 1, sz + 2, sz + 2);
    cz.fill(cr);
    cz.set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
    cz.set_line_join(cr, CAIRO_LINE_JOIN_ROUND);

    cx = x + sz / 2.0; cy = y + sz / 2.0;

    if ((itype & 0xff) == 2) {                           /* XmONE_OF_MANY -> radio circle */
        r = sz / 2.0 - 1.5;
        cz.new_sub_path(cr);
        cz.arc(cr, cx, cy, r, 0, 6.2832);
        r5_ind_col(cr, R5_COL_WHITE, dim, bg);
        cz.fill(cr);
        cz.new_sub_path(cr);
        cz.arc(cr, cx, cy, r, 0, 6.2832);
        cz.set_line_width(cr, 1.3);
        r5_ind_col(cr, R5_COL_EDGE, dim, bg);
        cz.stroke(cr);
        if (set) {                                       /* filled accent dot */
            cz.new_sub_path(cr);
            cz.arc(cr, cx, cy, r * 0.48, 0, 6.2832);
            r5_ind_col(cr, R5_COL_ACCENT, dim, bg);
            cz.fill(cr);
        }
    } else {                                             /* XmN_OF_MANY -> checkbox square */
        double bx = x + 1.0, by = y + 1.0, bs = sz - 2.0, rr = 2.5;
        /* rounded-square path */
        cz.new_sub_path(cr);
        cz.arc(cr, bx + bs - rr, by + rr,      rr, -1.5708, 0);
        cz.arc(cr, bx + bs - rr, by + bs - rr, rr, 0,       1.5708);
        cz.arc(cr, bx + rr,      by + bs - rr, rr, 1.5708,  3.1416);
        cz.arc(cr, bx + rr,      by + rr,      rr, 3.1416,  4.7124);
        cz.close_path(cr);
        r5_ind_col(cr, set ? R5_COL_ACCENT : R5_COL_WHITE, dim, bg);
        cz.fill(cr);
        /* outline: same path again */
        cz.new_sub_path(cr);
        cz.arc(cr, bx + bs - rr, by + rr,      rr, -1.5708, 0);
        cz.arc(cr, bx + bs - rr, by + bs - rr, rr, 0,       1.5708);
        cz.arc(cr, bx + rr,      by + bs - rr, rr, 1.5708,  3.1416);
        cz.arc(cr, bx + rr,      by + rr,      rr, 3.1416,  4.7124);
        cz.close_path(cr);
        cz.set_line_width(cr, 1.3);
        r5_ind_col(cr, set ? R5_COL_ACCENT : R5_COL_EDGE, dim, bg);
        cz.stroke(cr);
        if (set) {                                       /* white checkmark */
            cz.new_sub_path(cr);
            cz.move_to(cr, bx + bs * 0.24, by + bs * 0.52);
            cz.line_to(cr, bx + bs * 0.44, by + bs * 0.72);
            cz.line_to(cr, bx + bs * 0.78, by + bs * 0.28);
            cz.set_line_width(cr, 1.6);
            r5_ind_col(cr, R5_COL_WHITE, dim, bg);
            cz.stroke(cr);
        }
    }
}

/* ---- radio / checkbox indicators, drawn with cairo (antialiased) ----
 * DrawToggle is Motif's indicator painter, called from expose AND from every arm/select/disarm
 * redraw. We take over the whole toggle EXPOSE below (background + indicator + label, buffered), so
 * on expose Motif draws none of it. But arm/select/disarm repaint the indicator through THIS
 * function WITHOUT a full expose, so we take it over too: it repaints just the indicator cell, into
 * a back buffer, so every interactive redraw path is ours and none of them flickers.
 *
 * cdecl (Widget w) — 1 arg, plain ret, verified. Geometry mirrors Motif: the cell is at
 * highlightThickness+shadowThickness+marginWidth, the drawn indicator is clamped to the widget
 * height (Motif draws well under indicatorSize) and centered in the cell. */
void retro5_DrawToggle(void *w) {
    Display *dpy;
    Window win, root;
    unsigned int ww, hh, bwid, dep;
    int wx, wy, x, y, sz;
    R5Canvas cv;
    cairo_t *cr;
    R5Arg a[7];
    long set = 0, itype = 0, hlt = 0, st = 0, mw = 0, dim = 0, height = 0, edge;
    unsigned long bg = 0xd3d3d3;

    if (!r5_skin || !w || !r5_cairo()) return;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return;
    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bwid, &dep)) return;

    if (r5_trace) {                                       /* discover the toggle class record + expose */
        void *cls = *(void **)((char *)w + 4);
        void *exp = (cls && !range_unmapped((char *)cls + R5_EXPOSE_OFF, 4))
                    ? *(void **)((char *)cls + R5_EXPOSE_OFF) : 0;
        char b[128];
        int k = snprintf(b, sizeof b, "toggle w=%p class=%p expose=%p name=%s\n",
                         w, cls, exp, r5_widget_class(w) ? r5_widget_class(w) : "?");
        if (k > 0) write(2, b, (size_t)k);
    }

    a[0].name = (char *)"set";                a[0].value = (long)&set;
    a[1].name = (char *)"indicatorType";      a[1].value = (long)&itype;
    a[2].name = (char *)"highlightThickness"; a[2].value = (long)&hlt;
    a[3].name = (char *)"shadowThickness";    a[3].value = (long)&st;
    a[4].name = (char *)"marginWidth";        a[4].value = (long)&mw;
    a[5].name = (char *)"indicatorSize";      a[5].value = (long)&dim;
    a[6].name = (char *)"background";         a[6].value = (long)&bg;
    r5_get(w, a, 7);

    /* Dimension resources are 16-bit; mask off any high-word garbage. */
    hlt &= 0xffff; st &= 0xffff; mw &= 0xffff; dim &= 0xffff;
    height = (long)hh;
    if (dim <= 0 || dim >= 0xffff) dim = 13;
    /* Size the indicator from the widget height so it scales with the font (Motif grows the toggle
     * with the font). Fill most of the usable height for a modern look, but stay inside the cell
     * Motif reserved (indicatorSize) so the label — placed by Motif after that cell — is never
     * clipped. */
    edge = height - 2 * (hlt + st);
    { long hi = (long)(13 * r5_scale());                 /* cap grows with the UI scale */
      if (edge > hi) edge = hi; }
    if (edge < 10) edge = 10;
    sz = (int)edge;
    /* Hug the widget's left edge (drop the highlight margin) so a clear gap opens before the label,
     * which Motif has already placed for its own smaller indicator and which we don't move. */
    x  = (int)(st + mw);
    y  = (int)((height - edge) / 2);
    if (sz < 6 || x < 0 || y < 0) return;

    /* Draw the indicator off-screen and blit only its cell (Motif still paints the widget background
     * and the label; we own the indicator cell alone — see the double-buffer banner). */
    if (!r5_canvas_begin(&cv, dpy, win, ww, hh)) return;
    if (!(cr = r5_canvas_cairo(&cv))) { r5_canvas_commit(&cv, 0, 0, 0, 0); return; }

    r5_paint_indicator(cr, x, y, sz, itype, set, bg, r5_insensitive(w));
    {
        /* blit just the indicator cell (the region we cleared + drew), clamped to the widget */
        int bx = x - 1, by = y - 1;
        int bw2 = sz + 2, bh2 = sz + 2;
        if (bx < 0) { bw2 += bx; bx = 0; }
        if (by < 0) { bh2 += by; by = 0; }
        if (bx + bw2 > (int)ww) bw2 = (int)ww - bx;
        if (by + bh2 > (int)hh) bh2 = (int)hh - by;
        if (bw2 < 0) bw2 = 0;
        if (bh2 < 0) bh2 = 0;
        r5_canvas_commit(&cv, bx, by, (unsigned)bw2, (unsigned)bh2);
    }
}

/* Full XmToggleButton expose — background + indicator + label, ALL double-buffered. We draw the
 * background and our cairo indicator into a back-buffer pixmap, then run Motif's own XmLabel expose
 * with its text redirected into that SAME pixmap (so the label keeps Motif's exact font/size/position
 * but lands off-screen), and blit the finished widget in ONE XCopyArea. This is what ends the group
 * flicker: Motif's stock toggle expose clears each widget's background straight on the window, so
 * unsetting siblings in a radio group flashes a clear across every one of them; here nothing — not
 * even the label — reaches the screen until the single blit.
 *
 * Reentry guard: the Motif-fallback path calls the toggle's original Redisplay, which itself calls
 * the (now taken-over) XmLabel expose — see retro5_LabelExpose — which would route straight back here.
 * The flag turns that into a one-shot so it can never recurse. */
static void (*r5_orig_toggle_expose)(void *, XEvent *, Region);
static void (*r5_orig_label_expose)(void *, XEvent *, Region);   /* real XmLabel expose (draws label) */
static int r5_in_toggle_expose;

void retro5_ToggleButtonExpose(void *w, XEvent *ev, Region region) {
    Display *dpy;
    Window win, root;
    unsigned int ww, hh, bwid, dep;
    int wx, wy, x, y, sz;
    R5Canvas cv;
    cairo_t *cr;
    R5Arg a[7];
    long set = 0, itype = 0, hlt = 0, st = 0, mw = 0, height, edge;
    unsigned long bg = 0xd3d3d3;
    Pixmap pm = 0;

    if (r5_in_toggle_expose) return;                     /* never recurse via the fallback path */

    if (!r5_skin || !w || !r5_cairo() || !r5_xlib()) goto fallback;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return;                            /* no window yet: nothing to paint, no fallback */
    r5_take_highlight(w);                                /* stop Motif's enter/leave border flicker */
    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bwid, &dep)) goto fallback;

    a[0].name = (char *)"set";                a[0].value = (long)&set;
    a[1].name = (char *)"indicatorType";      a[1].value = (long)&itype;
    a[2].name = (char *)"highlightThickness"; a[2].value = (long)&hlt;
    a[3].name = (char *)"shadowThickness";    a[3].value = (long)&st;
    a[4].name = (char *)"marginWidth";        a[4].value = (long)&mw;
    a[5].name = (char *)"background";         a[5].value = (long)&bg;
    a[6].name = (char *)"labelPixmap";        a[6].value = (long)&pm;
    r5_get(w, a, 7);

    /* PIXMAP toggle (a toolbar icon toggle like the "as-you-type" abc buttons): it has no radio/
     * checkbox indicator — the whole face is an icon that latches pressed when set. Motif redraws its
     * pixmap via redisplayPixmap (XClearArea + XCopyArea straight on the window), which flickers on
     * every repaint and which our text redirect does not catch. So we own it here: draw the face
     * (pressed/inset when set) and blit the icon centered, entirely in the back buffer — one flicker-
     * free frame, no bogus indicator, no Motif drawing. */
    if (pm && pm != R5_UNSPECIFIED_PIXMAP) {
        Pixmap root2; int ppx, ppy, ix, iy; unsigned pw, ph, pbw, pdep;
        if (!r5x.GetGeometry(dpy, pm, &root2, &ppx, &ppy, &pw, &ph, &pbw, &pdep)) goto fallback;
        if ((pdep != 1 && pdep != dep) || ww < 4 || hh < 4) goto fallback;
        if (!r5_canvas_begin(&cv, dpy, win, ww, hh)) goto fallback;
        {
            Drawable dst = cv.buf;
            GC face = set ? r5_pick(dpy, dst, R5_GC_PRESS) : r5_gc_for_pixel(dpy, dst, bg);
            if (face) r5x.FillRectangle(dpy, dst, face, 0, 0, ww, hh);
            if (set) r5_inset(dpy, dst, 0, 0, (int)ww, (int)hh);   /* latched -> pressed frame */
            ix = ((int)ww - (int)pw) / 2 + (set ? 1 : 0);
            iy = ((int)hh - (int)ph) / 2 + (set ? 1 : 0);
            if (pdep == 1) {
                GC g = r5_pick(dpy, dst, R5_GC_GLYPH);
                if (g) r5x.CopyPlane(dpy, pm, dst, g, 0, 0, pw, ph, ix, iy, 1);
            } else {
                GC g = r5_gc_for_pixel(dpy, dst, bg);
                if (g) r5x.CopyArea(dpy, pm, dst, g, 0, 0, pw, ph, ix, iy);
            }
            r5_carve_corners(dpy, dst, w, ww, hh);
        }
        r5_canvas_commit(&cv, 0, 0, ww, hh);
        return;
    }

    hlt &= 0xffff; st &= 0xffff; mw &= 0xffff;
    height = (long)hh;
    edge = height - 2 * (hlt + st);                      /* same indicator geometry as DrawToggle */
    { long hi = (long)(13 * r5_scale());
      if (edge > hi) edge = hi; }
    if (edge < 10) edge = 10;
    sz = (int)edge;
    x  = (int)(st + mw);
    y  = (int)((height - edge) / 2);
    if (sz < 6 || x < 0 || y < 0) goto fallback;

    if (!r5_canvas_begin(&cv, dpy, win, ww, hh)) goto fallback;
    if (!(cr = r5_canvas_cairo(&cv))) { r5_canvas_commit(&cv, 0, 0, 0, 0); goto fallback; }

    /* whole-widget background */
    cz.set_source_rgb(cr, R5_RD(bg), R5_GD(bg), R5_BD(bg));
    cz.rectangle(cr, 0, 0, (double)ww, (double)hh);
    cz.fill(cr);

    r5_paint_indicator(cr, x, y, sz, itype, set, bg, r5_insensitive(w));

    /* Solidify the background + indicator into the pixmap (flush cairo, then drop the cairo objects
     * but KEEP the pixmap), so Motif's Xlib drawing lands on top of them. */
    cz.surface_flush(cv.sf);
    cz.destroy(cv.cr);
    cz.surface_destroy(cv.sf);
    cv.cr = 0; cv.sf = 0;

    /* Paint the LABEL into the SAME back buffer via Motif's own XmLabel expose, with its text draws
     * redirected from the window to our pixmap. The label thus comes out in the toggle's exact font,
     * size and TextRect position (XmLabel draws the text via _XmStringDraw, whose glyphs flow through
     * our cairo text hook), yet lands off-screen with the rest of the frame — so the whole toggle,
     * label included, reaches the screen in ONE blit with no flicker and no double draw. */
    if (r5_orig_label_expose) {
        r5_redir_from = win;
        r5_redir_to   = cv.buf;
        r5_orig_label_expose(w, ev, region);
        r5_redir_from = 0; r5_redir_to = 0;
    }

    r5_canvas_commit(&cv, 0, 0, ww, hh);                 /* present the whole toggle in one blit */
    return;

fallback:
    if (r5_orig_toggle_expose) {
        r5_in_toggle_expose = 1;                         /* Redisplay re-enters XmLabel expose (ours) */
        r5_orig_toggle_expose(w, ev, region);
        r5_in_toggle_expose = 0;
    }
}

/* The shared XmLabel expose (XmToggleButton's superclass). Motif redraws a toggle's label on arm/
 * select/disarm by calling xmLabelClassRec.core_class.expose DIRECTLY — a path that bypasses the
 * toggle's own expose entirely — so without owning it too, that redraw would paint a SECOND copy of
 * the label over ours (offset, wrecking the antialiasing). We take it over: a toggle routes to our
 * full painter (one label, our position, no double); every other label-derived widget falls straight
 * through to Motif, unchanged. r5_toggle_class is the XmToggleButton class record for this build. */
static uintptr_t r5_toggle_class;

void retro5_LabelExpose(void *w, XEvent *ev, Region region) {
    if (w && r5_toggle_class && *(void **)((char *)w + 4) == (void *)r5_toggle_class) {
        retro5_ToggleButtonExpose(w, ev, region);
        return;
    }
    if (r5_orig_label_expose) r5_orig_label_expose(w, ev, region);
}

/* ======================================================================================= *
 *  Per-binary fix routines — each concentrated, self-contained, and obvious
 * ======================================================================================= */

/* ---- system-font injection ------------------------------------------------------------------
 * Append records to WP's font-record table so extra faces appear in the (now-unfiltered) selector.
 * Runs AFTER WP's own table builder via a trampoline detour, so it re-applies on every rebuild
 * (printer/.prs change). Replicates the 32-byte record contract (FONT-RENDERING-MAP §12): grow the
 * ptr array + remap table, calloc each record, set name (+0x10), a stock .pfb (+0x08 so WP's Type1
 * resolver never faults on a null path), alias self (+0x1c=0xffff), category 0 (+0x1e, lists), claim
 * a fontcode top-down from the free-code counter, and index remap[0xfff-code]=slot. Bounded well
 * under the 4096-fontcode ceiling. PHASE 1: a fixed test list to validate the mechanism safely;
 * fontconfig enumeration replaces r5_inject_list next. Gated by RETRO5_ALLFONTS. */
extern void *calloc(size_t, size_t);
extern void *realloc(void *, size_t);
extern char *strdup(const char *);

static int (*r5_builder_orig)(void);                 /* trampoline to the real font-table builder */
static int  r5_inj_base;                             /* table count just before our injection */

/* Enumerate installed system font FAMILIES via libfontconfig (deduped, case-insensitive). Fills
 * r5_fcfam. dlopen'd RTLD_DEEPBIND (NOLOAD first — cairo has usually already loaded it) so its libc
 * calls bind to glibc, not our libc5 shims. Best-effort: 0 families on any failure -> nothing injected. */
static char r5_fcfam[2048][64];
static int  r5_fcfam_n;
/* A family name WP can actually store & reproduce: its .wpd font storage is a legacy
 * codepage, not UTF-8, so names with non-ASCII bytes (CJK, many localized names) would be mangled.
 * Skip anything outside printable ASCII until/unless we do a two-way codepage conversion. */
static int r5_wp_storable_name(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; s++) if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e) return 0;
    return 1;
}
static void r5_fc_enumerate(void) {
    void *h; void *(*FcInitLoadConfigAndFonts)(void); void *(*FcPatternCreate)(void);
    void *(*FcObjectSetBuild)(const char *, void *); void *(*FcFontList)(void *, void *, void *);
    int (*FcPatternGetString)(void *, const char *, int, unsigned char **);
    void *cfg, *pat, *os, *fs; int nfont, i, j;
    unsigned char **fonts;
    if (r5_fcfam_n) return;                              /* once */
    h = dlopen("libfontconfig.so.1", RTLD_NOLOAD | RTLD_NOW);
    if (!h) h = dlopen("libfontconfig.so.1", RTLD_NOW | RTLD_DEEPBIND);
    if (!h) return;
    /* FcInitLoadConfigAndFonts builds a FRESH config AND scans every configured font dir, so we see
     * the whole library — not the partial current config cairo warmed (which showed only ~230). */
    FcInitLoadConfigAndFonts = (void *(*)(void))dlsym(h, "FcInitLoadConfigAndFonts");
    FcPatternCreate    = (void *(*)(void))dlsym(h, "FcPatternCreate");
    FcObjectSetBuild   = (void *(*)(const char *, void *))dlsym(h, "FcObjectSetBuild");
    FcFontList         = (void *(*)(void *, void *, void *))dlsym(h, "FcFontList");
    FcPatternGetString = (int (*)(void *, const char *, int, unsigned char **))dlsym(h, "FcPatternGetString");
    if (!FcInitLoadConfigAndFonts || !FcPatternCreate || !FcObjectSetBuild || !FcFontList
        || !FcPatternGetString) return;
    /* WP is 32-bit; the system fontconfig cache in ~/.cache/fontconfig is 64-bit (le64) only, so the
     * in-process 32-bit fontconfig can't use it and returns a stale partial set (~230 of 2446 fonts).
     * Point it at a retro5-owned cache dir so it builds its OWN full 32-bit cache: first launch scans
     * everything (~2s extra), every launch after reads the le32 cache (fast). Env only affects our
     * fresh config below; not restored (WP is pre-XDG and creates no further fontconfig configs). */
    { const char *home = getenv("HOME"); static char xe[256];
      if (home) { char d[220]; extern int mkdir(const char *, unsigned int); extern int putenv(char *);
        snprintf(d, sizeof d, "%s/.cache/retro5-fc", home); mkdir(d, 0755);
        snprintf(xe, sizeof xe, "XDG_CACHE_HOME=%s", d); putenv(xe); } }
    cfg = FcInitLoadConfigAndFonts();
    pat = FcPatternCreate();
    os  = FcObjectSetBuild("family", (void *)0);        /* variadic, NULL-terminated */
    if (!cfg || !pat || !os) return;
    fs = FcFontList(cfg, pat, os);                      /* full config -> all font dirs */
    if (!fs) return;
    nfont = *(int *)fs;                                 /* FcFontSet: {int nfont; int sfont; FcPattern**} */
    fonts = *(unsigned char ***)((char *)fs + 8);
    if (r5_trace) { char b[80]; int k = snprintf(b, sizeof b, "retro5: fontconfig nfont=%d\n", nfont);
                    if (k > 0) write(2, b, (size_t)k); }
    for (i = 0; i < nfont && r5_fcfam_n < (int)(sizeof r5_fcfam / sizeof r5_fcfam[0]); i++) {
        unsigned char *fam = 0;
        if (FcPatternGetString(fonts[i], "family", 0, &fam) != 0 || !fam || !fam[0]) continue;
        if (!r5_wp_storable_name((const char *)fam)) continue;   /* WP codepage can't store it */
        for (j = 0; j < r5_fcfam_n; j++)                /* dedup, case-insensitive */
            if (!strcasecmp(r5_fcfam[j], (const char *)fam)) break;
        if (j < r5_fcfam_n) continue;
        strncpy(r5_fcfam[r5_fcfam_n], (const char *)fam, sizeof r5_fcfam[0] - 1);
        r5_fcfam[r5_fcfam_n][sizeof r5_fcfam[0] - 1] = 0;
        r5_fcfam_n++;
    }
}

static void r5_inject_fonts(void) {
    uint32_t *arr; unsigned short *remap; unsigned cnt, cap, code; int n, i;
    if (!r5_allfonts || !r5s.fontrec_arr || !r5s.remap_arr || !r5s.freecode) return;
    if (range_unmapped((void *)r5s.fontrec_arr, 4) || range_unmapped((void *)r5s.remap_arr, 4)) return;
    arr   = *(uint32_t **)r5s.fontrec_arr;
    remap = *(unsigned short **)r5s.remap_arr;
    if (!arr || !remap) return;
    cnt  = *(unsigned short *)r5s.fontrec_cnt;
    cap  = *(unsigned short *)r5s.fontrec_cap;
    code = *(unsigned short *)r5s.freecode;
    if (cnt < 1 || cnt > 4000 || code < 0x40) return;          /* sanity / leave code headroom */
    r5_fc_enumerate();
    n = r5_fcfam_n;
    if (n <= 0) return;
    if ((int)cnt + n > 4000) n = 4000 - (int)cnt;              /* stay under the 4096 fontcode ceiling */
    if (n <= 0) return;
    if (cnt + (unsigned)n > cap) {                             /* grow both arrays together */
        uint32_t *na = (uint32_t *)realloc(arr, (cnt + n) * 4);
        unsigned short *nr;
        if (!na) return;
        arr = na; *(uint32_t **)r5s.fontrec_arr = arr;
        nr = (unsigned short *)realloc(remap, (cnt + n) * 2);
        if (!nr) return;
        remap = nr; *(unsigned short **)r5s.remap_arr = remap;
        *(unsigned short *)r5s.fontrec_cap = (unsigned short)(cnt + n);
        if (r5s.remap_cap) *(unsigned short *)r5s.remap_cap = (unsigned short)(cnt + n);
    }
    r5_inj_base = (int)cnt;                                    /* first injected slot (for the render hook) */
    /* Template = a real base record: the list builder dereferences several fields (flags/source
     * pointers), so inherit them all from a known-good record, then override only what we own. */
    { extern void *memcpy(void *, const void *, size_t);
    unsigned char *tmpl = (arr[0] && !range_unmapped((void *)(uintptr_t)arr[0], 0x20))
                        ? (unsigned char *)(uintptr_t)arr[0] : 0;
    for (i = 0; i < n; i++) {
        unsigned char *rec = (unsigned char *)calloc(1, 0x20);
        if (!rec) break;
        if (tmpl) memcpy(rec, tmpl, 0x20);                     /* inherit valid fields from a real font */
        *(unsigned short *)(rec + 0x06) = (unsigned short)code;/* this record's OWN fontcode (was stale) */
        *(char **)(rec + 0x08) = strdup("wphv____.pfb");       /* stock face; resolver never faults */
        *(char **)(rec + 0x0c) = strdup(r5_fcfam[i]);          /* list-name (was stale template ptr) */
        *(char **)(rec + 0x10) = strdup(r5_fcfam[i]);          /* system family (selector display name) */
        *(char **)(rec + 0x14) = 0;                            /* no aux name */
        *(unsigned *)(rec + 0x18) = 0;                         /* lazy metric cache */
        *(unsigned short *)(rec + 0x1c) = 0xffff;              /* alias = self */
        *(unsigned char  *)(rec + 0x1e) = 0;                   /* category 0 -> lists */
        arr[cnt] = (uint32_t)(uintptr_t)rec;
        remap[0xfff - code] = (unsigned short)cnt;             /* claim the current free code */
        code--;
        cnt++;
    }
    }
    *(unsigned short *)r5s.fontrec_cnt  = (unsigned short)cnt;
    *(unsigned short *)r5s.freecode     = (unsigned short)code;
    if (r5s.fontrec_snap && !range_unmapped((void *)r5s.fontrec_snap, 2))
        *(unsigned short *)r5s.fontrec_snap = (unsigned short)cnt;   /* the F9 list iterates THIS */
    if (r5_trace) { char b[80]; int k = snprintf(b, sizeof b,
        "retro5: injected %d font(s), table count now %u\n", n, cnt);
        if (k > 0) write(2, b, (size_t)k); }
}

/* ---- §17.1: make injected faces first-class printer-font MEMBERS ----------------------------
 * The problem (handoff §2/§3): WP's font_code_to_record 0x085b69f0 validates a picked code against
 * the ACTIVE font-set's dense codemap; an injected code_index >= codemap.count MISSES, so WP rewrites
 * the stored code to the printer default (the "collapse") and the face reverts + shows the wrong name.
 * Forcing the membership gate alone SIGSEGVs because the face has no name-pool entry either.
 *
 * The fix (recipe §"The fix"): append a real codemap entry + font-entry for each injected face to the
 * active set, and intern its name in the pool, so font_printres_member finds it naturally, the name
 * read lands on real UTF-16, the code survives to the document, and the resolver renders it distinctly.
 *
 * STEP-0 LIVE RESULT (Xvfb :167, this exact build): *0x087bddf8 (0xa062380, the "base/display" font
 * resource) != *0x08812f90 (0xa047bb0, the printer resource).  font_code_to_record's resource_ctx_push
 * copies 0x087bddf8/fc INTO 0x08812f90/8c BEFORE the membership check, so the set actually checked is
 * element (token) of the container at *0x087bddf8 — NOT the printer resource.  So we append THERE.
 *   base set0 at rest: set+0x02 count=1, codemap(+0x18) count=127 (elem 0xa8), entries(+0x1c) count=127
 *   (elem 0x14).  Base display faces hold codes 0xfff..0xf81 (codemap idx 0..126); retro5's freecode
 *   injection continues at 0xf80 downward, so injected display slot i (127..N-1) already carries code
 *   0xfff-i, i.e. code_index == i == the codemap slot a sequential append lands in.  ALIGNMENT IS FREE:
 *   we verify 0xfff-code == codemap.count per face and append in display order; no code reassignment.
 *
 * Primitives are pure/self-contained (recipe) and called at their 8.0 VAs from inside WP (this runs as
 * the builder detour / hook, i.e. WP's own context — calling them is exactly what WP does). Idempotent:
 * appends once, when the base set is populated; re-tries (no-op) until then. Gated by RETRO5_ALLFONTS. */
typedef int   (*r5_res_append_fn)(void *c, const void *src);                 /* 0x0841fe50 -> 1 ok */
typedef int   (*r5_namepool_add_fn)(const void *u16, unsigned short blen,
                                    unsigned short out[2], char append);     /* 0x0840e600 -> 1 ok */
typedef void *(*r5_res_get_fn)(void *c, unsigned idx);                        /* 0x08420140 */
#define R5_RES_APPEND   ((r5_res_append_fn)0x0841fe50)
#define R5_NAMEPOOL_ADD ((r5_namepool_add_fn)0x0840e600)
#define R5_RES_GET      ((r5_res_get_fn)0x08420140)

static int r5_membership_added;      /* one-shot: appended for the current base set */
static int r5_member_limit;          /* RETRO5_MEMBERS: cap appended faces (de-risk); 0 = all */

/* Read a WpResContainer's live element count (+0x14). */
static unsigned r5_ctr_count(void *c) { return *(unsigned *)((char *)c + 0x14); }

static void r5_fontres_add_members(void) {
    void *base_res, *set, *codemap, *entries, *by_name, *tcm, *te;
    uint32_t *arr; unsigned reccnt, defidx, first_code, i; int added = 0;
    unsigned char cm[0xa8], fe[0x14], bn[0xc]; int have_bn = 0; /* templated entry copies */
    if (!r5_allfonts || r5_membership_added || r5_inj_base <= 0) return;
    if (!r5s.fontrec_arr || !r5s.fontrec_cnt) return;
    if (range_unmapped((void *)0x087bddf8, 4) || range_unmapped((void *)0x087bddfc, 2)) return;
    if (range_unmapped((void *)r5s.fontrec_arr, 4) || range_unmapped((void *)r5s.fontrec_cnt, 2)) return;

    base_res = *(void **)0x087bddf8;                     /* container active at the membership check */
    if (!base_res || range_unmapped(base_res, 0x34)) return;
    set = R5_RES_GET(base_res, *(unsigned short *)0x087bddfc);   /* element 0 = the font-set */
    if (!set || range_unmapped(set, 0x24)) return;
    if (*(unsigned short *)((char *)set + 0x02) == 0) return;    /* set not built yet -> retry later */
    codemap = *(void **)((char *)set + 0x18);
    entries = *(void **)((char *)set + 0x1c);
    if (!codemap || range_unmapped(codemap, 0x34) || !entries || range_unmapped(entries, 0x34)) return;
    /* §17.1 (2nd pass): the NAME->code re-resolver on the APPLY path searches the font-set's by_name
     * (+0x20) 12-byte index (see printer_fontset_face_add 0x08416b10). Membership populated codemap+
     * entries+namepool but NOT by_name, so injected names miss and collapse to the nearest base face.
     * Also append a by_name record per injected face. Template = by_name[0] (default) so the non-key
     * bytes (+0x08 flag/+0x09 weight/+0x0a) stay sane; we patch name_block/offset + code_index. */
    by_name = *(void **)((char *)set + 0x20);
    if (by_name && !range_unmapped(by_name, 0x34) && r5_ctr_count(by_name) > 0) {
        void *b0 = R5_RES_GET(by_name, 0);
        if (b0 && !range_unmapped(b0, 0xc)) { memcpy(bn, b0, 0xc); have_bn = 1; }
    }

    arr    = *(uint32_t **)r5s.fontrec_arr;
    reccnt = *(unsigned short *)r5s.fontrec_cnt;
    if (!arr || range_unmapped(arr, 4) || reccnt <= (unsigned)r5_inj_base) return;

    /* Alignment gate (also the "base set populated?" gate): the first injected face's code_index must
     * equal the current codemap append slot.  If not, the base set isn't the 127-face set yet (or codes
     * drifted) -> bail WITHOUT marking done, so we retry on the next hook. */
    { unsigned char *r0 = (unsigned char *)(uintptr_t)arr[r5_inj_base];
      if (!r0 || range_unmapped(r0, 0x20)) return;
      first_code = *(unsigned short *)(r0 + 0x06); }
    if ((unsigned)(0xfff - first_code) != r5_ctr_count(codemap)) {
        if (r5_trace) { char b[96]; int k = snprintf(b, sizeof b,
            "retro5: §17.1 not ready (codemap.count=%u, want %u) — retry\n",
            r5_ctr_count(codemap), 0xfff - first_code); if (k > 0) write(2, b, (size_t)k); }
        return;
    }

    /* Template = the printer default face's codemap entry + its metric entry (sane size_denom etc). */
    defidx = 0xfff - ((*(unsigned *)0x087bdfe4 >> 16) & 0xfff);
    tcm = R5_RES_GET(codemap, defidx);
    if (!tcm || range_unmapped(tcm, 0xa8)) return;
    te  = R5_RES_GET(entries, *(short *)((char *)tcm + 0x04));
    if (!te || range_unmapped(te, 0x14)) return;
    memcpy(cm, tcm, 0xa8);
    memcpy(fe, te, 0x14);

    for (i = (unsigned)r5_inj_base; i < reccnt; i++) {
        unsigned char *rec = (unsigned char *)(uintptr_t)arr[i];
        const char *name; unsigned short code, code_index, out[2]; unsigned short u16[128];
        int j, entry_idx; unsigned short blen;
        if (r5_member_limit && added >= r5_member_limit) break;
        if (!rec || range_unmapped(rec, 0x20)) break;
        code       = *(unsigned short *)(rec + 0x06);
        code_index = (unsigned short)(0xfff - code);
        name       = (const char *)(uintptr_t)(*(uint32_t *)(rec + 0x10));
        if (!name || range_unmapped(name, 1) || !name[0]) break;
        /* per-face alignment: the append must land exactly at code_index */
        if (code_index != r5_ctr_count(codemap)) break;
        /* ASCII family -> UTF-16LE (WP names are 16-bit); NUL-terminated. */
        for (j = 0; j < 126 && name[j]; j++) u16[j] = (unsigned char)name[j];
        u16[j] = 0;
        blen = (unsigned short)((j + 1) * 2);            /* bytes incl. terminator (== utf16len+2) */
        if (!R5_NAMEPOOL_ADD(u16, blen, out, 1)) break;
        /* append the metric entry, then the codemap entry that points at it */
        if (!R5_RES_APPEND(entries, fe)) break;
        entry_idx = (int)r5_ctr_count(entries) - 1;
        *(unsigned short *)(cm + 0x00) = code_index;     /* this slot's own index      */
        *(short          *)(cm + 0x04) = (short)entry_idx;/* -> entries[entry_idx]     */
        *(unsigned short *)(cm + 0x0a) = out[0];         /* name-pool block            */
        *(unsigned short *)(cm + 0x0c) = out[1];         /* name-pool byte offset      */
        *(unsigned short *)(cm + 0xa6) = 0xffff;         /* end of sort chain          */
        if (!R5_RES_APPEND(codemap, cm)) break;          /* lands at index code_index  */
        /* by_name index: {name_block,name_offset,code_index,code_index_dup,flag,weight,param4} */
        if (have_bn) {
            *(unsigned short *)(bn + 0x00) = out[0];      /* name-pool block  */
            *(unsigned short *)(bn + 0x02) = out[1];      /* name-pool offset */
            *(unsigned short *)(bn + 0x04) = code_index;  /* -> the injected code */
            *(unsigned short *)(bn + 0x06) = code_index;  /* dup (see 0x08416b10) */
            R5_RES_APPEND(by_name, bn);                   /* non-fatal if it fails */
        }
        added++;
    }
    r5_membership_added = (added > 0);                   /* mark done only if we actually appended */
    if (r5_trace) { char b[160]; int k = snprintf(b, sizeof b,
        "retro5: §17.1 added %d injected face(s) as members (codemap=%u by_name=%u have_bn=%d)\n",
        added, r5_ctr_count(codemap), by_name ? r5_ctr_count(by_name) : 0, have_bn);
        if (k > 0) write(2, b, (size_t)k); }
}

/* Builder detour: run WP's real builder (trampoline), then append our fonts. Same 6-byte prologue
 * on both builds (55 89 e5 83 ec 0c), so keep=6. */
static int retro5_font_builder(void) {
    int r = r5_builder_orig ? r5_builder_orig() : 0;
    r5_inject_fonts();
    r5_fontres_add_members();       /* §17.1: real fix — make injected faces genuine members */
    return r;
}
static void r5_install_injection(void) {
    static const unsigned char g[] = {0x55,0x89,0xe5,0x83,0xec,0x0c};
    if (!r5_allfonts || !r5s.builder_va) return;
    if (range_unmapped((void *)r5s.builder_va, sizeof g) || memcmp((void *)r5s.builder_va, g, sizeof g))
        return;
    r5_builder_orig = (int (*)(void))r5_make_trampoline(r5s.builder_va, 6);
    if (r5_builder_orig)
        patch_entry(r5s.builder_va, (const char *)g, sizeof g, (void *)retro5_font_builder);
}

/* ---- printer-font COLLECTION injection (the printer-driven picker source) --------------------
 * WP has TWO ways a font picker (F9 Font-Face + the toolbar font combos) gets its list, depending on
 * the active printer:
 *   (a) NO real printer / fallback (the common Linux case, RETRO5_CUPS=0): the pickers enumerate the
 *       merged font-record table 0x08808754 directly, filtered by record+0x1e. The record-table
 *       injection above (RETRO5_ALLFONTS) already grows that table AND r5_apply_allfonts NOPs the
 *       filter, so system families LIST + select + render with NO help from this function. (Verified
 *       live: with RETRO5_FONTCOLL=0, both F9 and the toolbar combo still list DejaVu/Liberation/etc.)
 *   (b) A real printer with a .prs selected (§13.7): the picker instead reads the per-dialog printer
 *       "collection" (COLL) built by fontcoll_build 0x0852acd0 from that printer's fonts — which does
 *       NOT contain our injected records. There the record-table injection is invisible and this
 *       COLL-append is what makes injected families appear.
 * So this detour is the (b) half of "list in EVERY picker regardless of printer": it appends a
 * FaceEntry to COLL for each system record we injected, each carrying a StyleVar whose packed fontcode
 * (code<<16) remaps 1:1 back to our injected record — so selecting it reaches the resolver with a code
 * that resolves to the right family (no substitution), and RETRO5_DOCFONT renders it via cairo. On the
 * (a) config it is redundant but harmless (the pickers read the record table, not COLL, so it adds no
 * duplicates — verified: FONTCOLL=0 and FONTCOLL=1 produce identical lists).
 *
 * Structures (LIVE-VERIFIED, names.txt / fontcoll_fill 0x0852af70 disassembly):
 *   COLL      { u32 count@+0; FaceEntry *entries@+4 }          (calloc(1,8), per-dialog)
 *   FaceEntry { u32 flags@+0 (live 0x87); void *faceRec@+4; u16 nstyles@+8; StyleVar *styles@+0xc }
 *   StyleVar  { u32 fontcode@+0 (code<<16); void *styleRec@+4; u32 0@+8; u32 0@+0xc }
 * faceRec and styleRec are NOT structs — fontcoll_fill mallocs each as a bare NUL-terminated name
 * string (faceRec = strcpy(family), styleRec = strcpy("Regular")). So there are NO other faceRec
 * fields to template: a strdup of the name is a complete, valid faceRec. flags is copied verbatim
 * from a real entry so any flag bits the enumerator/display read (0x87) are present.
 *
 * All work is bounds/mincore-guarded; a bad append degrades to "fewer fonts listed", never a fault.
 * Only appends the records r5_inject_fonts already added (so the codes are guaranteed live in the
 * record table).
 *
 * LIVE-VERIFIED 2026-07-13 (Xvfb :157, xwp 8.0, ALLFONTS=1 FONTCOLL=1 CUPS=0 DOCFONT=2, gdb): the
 * COLL-driven populate DOES work when it is the source — injected system families (Liberation
 * Sans/Serif/Mono, Helvetica, P052, Standard Symbols PS, STIX*, ...) list, are selectable, apply
 * without crash, and render via cairo in the picked family (no substitution).
 *
 * How the COLL populate works (corrects an earlier mis-diagnosis that claimed a parallel list-model C
 * stays at 62): when a COLL-sourced picker builds its list, f9_dialog_ctor's list-builder
 * 0x08522080(COLL) reads COLL->count (uint16) LIVE at populate time (`cmpw (%ecx)` / `movzwl (%ecx)`),
 * calloc's an array of that many display strings — one WP rich string per FaceEntry, name taken from
 * faceRec — and hands the widget items+itemCount = COLL->count. Because our detour has already grown
 * COLL by the time the ctor calls 0x08522080 (build is at 0x08520a3a, the builder call at 0x08520bf8),
 * the widget receives every appended item; timing is NOT a problem (the earlier note's worry that the
 * detour "runs too early" is moot — the builder re-reads COLL, it does not cache a count). The
 * list-model C at *(model[1]+0x140) that the earlier note fixated on is the SEARCH/SELECTION model,
 * walked by 0x086634e4 with the per-row +0xa byte marking the SELECTED row — NOT the list-populate
 * source; it also grows in step with COLL.
 *
 * Teardown is SAFE — verified across 23+ open/close/apply cycles with zero glibc free errors. On close,
 * fontcoll_destroy 0x0852b7d0 walks COLL->count and, per FaceEntry, frees: each StyleVar's styleRec
 * (style+4), the styles array (entry+0xc), and faceRec (entry+4); it frees style+0xc's deep pointer
 * ONLY iff (flags & 0x20). Our appended entries give it exactly that shape — faceRec = strdup(name),
 * styles = calloc(1,16) (one StyleVar), styleRec = strdup("Regular"), nstyles = 1, flags templated 0x87
 * (0x20 clear) — every freed pointer is an independent malloc block, so WP frees our entries cleanly.
 * Gated on RETRO5_ALLFONTS && RETRO5_FONTCOLL (FONTCOLL defaults to ALLFONTS). */
extern void free(void *);
extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
static void *(*r5_collbuild_orig)(void *, void *, unsigned, void *);

/* Alphabetise the picker: order two 16-byte FaceEntries by their faceRec name (the string at
 * entry+0x4), case-insensitively. Sorting the whole 16-byte record moves each entry's styles
 * pointer (entry+0xc -> StyleVar.fontcode) with it, so name<->fontcode<->record stays intact and
 * selection still resolves. A NULL/empty name sorts last so a bad entry never derails the compare. */
static int r5_faceentry_cmp(const void *a, const void *b) {
    const char *na = *(const char *const *)((const char *)a + 4);
    const char *nb = *(const char *const *)((const char *)b + 4);
    if (na == nb) return 0;
    if (!na) return 1;
    if (!nb) return -1;
    return strcasecmp(na, nb);
}

/* Is `name` one of the system families we injected into the record table (indices [inj_base,reccnt))?
 * Those records are the fontconfig faces that render via cairo (TTF/OTF); a base COLL entry carrying the
 * same name is the legacy Type1 (.pfb) face — WP's built-ins and any user-installed Type1 conversions.
 * Matching against the actually-injected record names (not the raw fontconfig list) guarantees a dropped
 * base face always HAS a surviving TTF replacement, even if injection was truncated at the code ceiling.
 * Case-insensitive; O(base*injected) but both sets are small and this runs once per dialog open. */
static int r5_name_is_injected(const char *name, uint32_t *arr, unsigned inj_base, unsigned reccnt) {
    unsigned i;
    if (!name || !*name) return 0;
    for (i = inj_base; i < reccnt; i++) {
        unsigned char *rec = (unsigned char *)(uintptr_t)arr[i];
        const char *nm;
        if (!rec || range_unmapped(rec, 0x14)) continue;
        nm = (const char *)(uintptr_t)(*(uint32_t *)(rec + 0x10));   /* record's family name (+0x10) */
        if (nm && !range_unmapped(nm, 1) && !strcasecmp(name, nm)) return 1;
    }
    return 0;
}

/* Free a base FaceEntry we are dropping, exactly as fontcoll_destroy 0x0852b7d0 would on dialog close —
 * so removing it from COLL leaks nothing, and because we also drop it from the array + count, WP never
 * double-frees it. Frees each StyleVar's styleRec (style+4), the styles array (entry+0xc), and faceRec
 * (entry+4). We deliberately do NOT touch the flags&0x20 "deep" pointer the destructor conditionally
 * frees: every base entry observed carries flags 0x87 (0x20 clear) so that branch is dead, and skipping
 * it removes any risk of a mis-offset free (worst case a leak that, in practice, never occurs). */
static void r5_free_faceentry(unsigned char *be) {
    unsigned nst = *(unsigned short *)(be + 8);
    unsigned char *styles = *(unsigned char **)(be + 0xc);
    char *faceRec = *(char **)(be + 4);
    unsigned k;
    if (styles && !range_unmapped(styles, (size_t)nst * 16)) {
        for (k = 0; k < nst; k++) {
            char *sr = *(char **)(styles + k * 16 + 4);
            if (sr) free(sr);
        }
        free(styles);
    }
    if (faceRec) free(faceRec);
}

static void r5_inject_collection(void *coll) {
    uint32_t *arr; unsigned reccnt, count, orig_count, ntotal, added, i;
    void **pentries; void *entries, *ne; unsigned char *fe; uint32_t flags0;
    if (!r5_allfonts || !r5_fontcoll || !coll || range_unmapped(coll, 8)) return;
    if (r5_inj_base <= 0) return;                            /* record-table injection never ran */
    if (!r5s.fontrec_arr || !r5s.fontrec_cnt
        || range_unmapped((void *)r5s.fontrec_arr, 4) || range_unmapped((void *)r5s.fontrec_cnt, 2))
        return;
    arr    = *(uint32_t **)r5s.fontrec_arr;
    reccnt = *(unsigned short *)r5s.fontrec_cnt;
    if (!arr || range_unmapped(arr, 4) || reccnt <= (unsigned)r5_inj_base || reccnt > 8000) return;
    ntotal = reccnt - (unsigned)r5_inj_base;                 /* # injected system records to mirror */

    count    = *(uint32_t *)coll;                            /* COLL.count  */
    orig_count = count;                                      /* base count before dedup (for the trace) */
    pentries = (void **)((char *)coll + 4);                  /* &COLL.entries */
    entries  = *pentries;
    if (count < 1 || count > 100000 || !entries || range_unmapped(entries, 16)) return;
    flags0 = *(uint32_t *)entries;                           /* template the flags dword from entry[0] */

    ne = realloc(entries, (size_t)(count + ntotal) * 16);
    if (!ne) return;
    entries = ne; *pentries = ne;

    /* Dedup, preferring TTF over Type1: drop (and free) every base FaceEntry whose name matches a
     * system family we injected -> the fontconfig/cairo (TTF/OTF) face wins, the legacy Type1 (.pfb)
     * face is removed. Compact survivors down; `count` becomes the deduped base count, and the injected
     * faces are appended after it, so each family lands exactly once. */
    {
        unsigned kept = 0, j;
        for (j = 0; j < count; j++) {
            unsigned char *be = (unsigned char *)entries + (size_t)j * 16;
            const char *nm = *(char **)(be + 4);
            if (nm && !range_unmapped(nm, 1)
                && r5_name_is_injected(nm, arr, (unsigned)r5_inj_base, reccnt)) {
                r5_free_faceentry(be);                          /* drop the Type1 duplicate cleanly */
                continue;
            }
            if (kept != j) memcpy((char *)entries + (size_t)kept * 16, be, 16);
            kept++;
        }
        count = kept;
    }

    fe = (unsigned char *)entries + (size_t)count * 16;
    added = 0;
    for (i = 0; i < ntotal; i++) {
        unsigned char *rec = (unsigned char *)(uintptr_t)arr[(unsigned)r5_inj_base + i];
        unsigned short code; const char *name; char *faceRec, *styleRec, *styles;
        if (!rec || range_unmapped(rec, 0x20)) continue;
        code = *(unsigned short *)(rec + 0x06);              /* this record's own fontcode */
        name = (const char *)(uintptr_t)(*(uint32_t *)(rec + 0x10));  /* +0x10 = system family name */
        if (!name || range_unmapped(name, 1) || !name[0]) continue;
        faceRec = strdup(name);                              /* faceRec IS the family name string */
        styleRec = strdup("Regular");
        styles  = (char *)calloc(1, 16);                     /* one StyleVar */
        if (!faceRec || !styleRec || !styles) { free(faceRec); free(styleRec); free(styles); continue; }
        *(uint32_t *)(styles + 0) = (uint32_t)code << 16;    /* packed fontcode -> remaps to our record */
        *(void   **)(styles + 4)  = styleRec;
        *(uint32_t *)(fe + 0)     = flags0;                  /* flags (templated) */
        *(void   **)(fe + 4)      = faceRec;
        *(uint32_t *)(fe + 8)     = 1;                       /* nstyles = 1 */
        *(void   **)(fe + 0xc)    = styles;
        fe += 16;
        added++;
    }
    *(uint32_t *)coll = count + added;                       /* publish new count */
    /* Alphabetise the WHOLE list (WP's base faces + our appended ones) by faceRec name, so the
     * picker reads A..Z merged instead of base-then-injected. Sorting the 16-byte FaceEntry records
     * keeps each entry's styles/fontcode with its name, so selection still resolves; the list-model
     * C and the display array are (re)built from these entries AFTER this hook, so they inherit the
     * order. faceRec holds the real name (the leading 'Q' in the cell is a chrome artifact, not in
     * the string), so this is a true alphabetical sort. */
    if (count + added > 1)
        qsort(entries, (size_t)(count + added), 16, r5_faceentry_cmp);
    if (r5_trace) { char b[128]; int k = snprintf(b, sizeof b,
        "retro5: collection +%u face(s), dropped %u Type1 dup(s), COLL count now %u (base was %u), sorted\n",
        added, orig_count - count, count + added, orig_count);
        if (k > 0) write(2, b, (size_t)k); }
}

/* Detour: run the real builder (trampoline, keep=9 for the 55 89 e5 81 ec 10 01 00 00 prologue),
 * take the COLL it returns in eax, and append our faces. Args are forwarded intact (cdecl). */
static void *retro5_fontcoll_build(void *a1, void *a2, unsigned a3, void *a4) {
    void *coll = r5_collbuild_orig ? r5_collbuild_orig(a1, a2, a3, a4) : 0;
    r5_inject_collection(coll);
    return coll;
}
static void r5_install_collection_injection(void) {
    static const unsigned char g[] = {0x55,0x89,0xe5,0x81,0xec,0x10,0x01,0x00,0x00};
    if (!r5_allfonts || !r5_fontcoll || !r5s.fontcoll_build_va) return;
    if (range_unmapped((void *)r5s.fontcoll_build_va, sizeof g)
        || memcmp((void *)r5s.fontcoll_build_va, g, sizeof g)) return;
    r5_collbuild_orig = (void *(*)(void *, void *, unsigned, void *))
                        r5_make_trampoline(r5s.fontcoll_build_va, 9);
    if (r5_collbuild_orig)
        patch_entry(r5s.fontcoll_build_va, (const char *)g, sizeof g, (void *)retro5_fontcoll_build);
}

/* ---- injected-font rendering (Phase 3) -------------------------------------------------------
 * Injected records all share WP's fallback (wphv) metric, so they can't be told apart at blit time
 * by metric name. Instead, hook the font RESOLVER (called with the packed fontcode on every font
 * activation): reproduce its own remap index (idx = 0xfff - ((code>>16) & 0xfff)), look up the slot,
 * and if it is one we injected, stash its real fontconfig family in r5_cur_family. r5_doc_family()
 * then renders the cairo glyph in that family. Cleared for stock fonts so they keep metric-name
 * matching. Gated with the doc-font canvas (RETRO5_DOCFONT) + injection (RETRO5_ALLFONTS). */
static int (*r5_resolver_orig)(unsigned);
int retro5_resolver(unsigned codeattr) {
    if (!r5_membership_added) r5_fontres_add_members();   /* §17.1 lazy safety net (cheap once done) */
    r5_cur_family[0] = 0;
    /* §17.1 REAL FIX: the base name->code hook (retro5_name_to_code) now keeps an injected face's OWN
     * display code through render + reload, so by the time we get here `codeattr` already carries the
     * injected code — the block below reads that record's real family straight from the table. (The old
     * r5_forced_family interim, which force-rendered the last pick for a COLLAPSED code, is obsolete and
     * was removed: the code no longer collapses.) */
    /* Capture the SELECTED font's own record name (+0x10) — WP substitutes display/injected fonts to
     * a stock face for its Type1 engine (e.g. "DejaVu Sans" -> BroadwayEngraved metric), so the metric
     * name is wrong; the record name is what the user picked. r5_doc_family renders from this. */
    if (r5s.remap_arr && r5s.fontrec_arr && r5s.fontrec_cnt
        && !range_unmapped((void *)r5s.remap_arr, 4) && !range_unmapped((void *)r5s.fontrec_arr, 4)) {
        unsigned short *remap = *(unsigned short **)r5s.remap_arr;
        uint32_t *arr = *(uint32_t **)r5s.fontrec_arr;
        unsigned cnt = *(unsigned short *)r5s.fontrec_cnt;
        unsigned idx = 0x0fff - ((codeattr >> 16) & 0x0fff);
        if (remap && arr && !range_unmapped(&remap[idx], 2)) {
            unsigned slot = remap[idx];
            if (slot < cnt && !range_unmapped(&arr[slot], 4) && arr[slot]
                && !range_unmapped((void *)(uintptr_t)(arr[slot] + 0x10), 4)) {
                const char *nm = (const char *)(uintptr_t)(*(unsigned *)(uintptr_t)(arr[slot] + 0x10));
                if (nm && !range_unmapped(nm, 1)) {
                    strncpy(r5_cur_family, nm, sizeof r5_cur_family - 1);
                    r5_cur_family[sizeof r5_cur_family - 1] = 0;
                }
            }
        }
    }
    return r5_resolver_orig ? r5_resolver_orig(codeattr) : 0;
}
static void r5_install_resolver_hook(void) {
    static const unsigned char g[] = {0x55,0x89,0xe5,0x83,0xec,0x08};
    if (!(r5_docfont || r5_docfont81) || !r5_allfonts || !r5s.resolver_va) return;
    if (range_unmapped((void *)r5s.resolver_va, sizeof g) || memcmp((void *)r5s.resolver_va, g, sizeof g))
        return;
    r5_resolver_orig = (int (*)(unsigned))r5_make_trampoline(r5s.resolver_va, 6);
    if (r5_resolver_orig)
        patch_entry(r5s.resolver_va, (const char *)g, sizeof g, (void *)retro5_resolver);
}

/* ---- injected-font SELECTION: ensure membership before the pick ----------------------------------
 * Hook the font-set command handler only to GUARANTEE the injected faces are already members of the
 * base set (r5_fontres_add_members) by the time a pick is classified — this keeps the F9 dialog's
 * "Resulting Font" showing the real injected name. The actual keep-the-code fix is elsewhere: the base
 * name->code hook (retro5_name_to_code) makes the render/reload path resolve an injected NAME to its own
 * display code, so nothing collapses and the resolver renders it distinctly. (The former r5_forced_family
 * interim — which force-rendered the last-picked face for a COLLAPSED code and so could not tell two
 * injected faces apart or survive reload — is obsolete and was removed.) cdecl (arg1, reqcode, op, arg4). */
static int (*r5_fontset_orig)(unsigned, unsigned, unsigned, unsigned);
int retro5_fontset(unsigned a1, unsigned reqcode, unsigned op, unsigned a4) {
    if (!r5_membership_added) r5_fontres_add_members();   /* §17.1: ensure membership before the pick */
    return r5_fontset_orig ? r5_fontset_orig(a1, reqcode, op, a4) : 0;
}
static void r5_install_fontset_hook(void) {
    static const unsigned char g[] = {0x55,0x89,0xe5,0x81,0xec,0x14,0x01,0x00,0x00};
    if (!(r5_docfont || r5_docfont81) || !r5_allfonts || !r5s.fontset_va) return;
    if (range_unmapped((void *)r5s.fontset_va, sizeof g) || memcmp((void *)r5s.fontset_va, g, sizeof g))
        return;
    r5_fontset_orig = (int (*)(unsigned, unsigned, unsigned, unsigned))
                      r5_make_trampoline(r5s.fontset_va, 9);
    if (r5_fontset_orig)
        patch_entry(r5s.fontset_va, (const char *)g, sizeof g, (void *)retro5_fontset);
}

/* ---- §17.1 REAL FIX: base-space NAME->code rescue (render + reload) --------------------------
 * ROOT CAUSE (live-verified, static-confirmed): the document stores the face NAME (not a code). On
 * render AND on reopen, WP turns that stored name into a 12-bit DISPLAY code via the base name->code
 * resolver FUN_085b7a20, which **bsearch()es** the display record table (fontrec_arr, count
 * fontrec_snap 0x0880875c) by name using comparator 0x085b7b10. bsearch REQUIRES a table sorted by
 * name; retro5 appends injected records at the END in fontconfig-enumeration order (UNSORTED), so
 * bsearch never finds an injected face and the resolver falls through to the printer default
 * (DAT_087bdfe4 -> 0xfff, or a fuzzy alias -> 0xff9). That collapsed code is what reaches the display
 * resolver 0x085b7860 (retro5_resolver), so injected text renders the substitute and reverts on reload.
 *
 * FIX: hook FUN_085b7a20. Run the original first (base faces + genuine hits keep working, untouched);
 * if it MISSES (returns 0 — it has just written the default to *out), convert the incoming UTF-16 name
 * to ASCII and match it against the injected records' family names (+0x10). On a hit, overwrite *out
 * with that record's own packed code (fontcode<<16) and return "found". Now every injected NAME resolves
 * to its OWN display code on every render and every reload: the resolver renders the right family,
 * multiple injected faces coexist (distinct codes), and it survives save/reload. Population of the
 * base by_name (r5_fontres_add_members) was never consulted here because this path is a bsearch over the
 * record TABLE, not a by_name walk — so this entry hook is the correct, targeted intercept. */
static int (*r5_name_to_code_orig)(void *, int *, unsigned);

/* UTF-16LE name -> ASCII (bounded, fault-free). Returns length, or -1 if unreadable. */
static int r5_u16_to_ascii(const void *name_u16, char *out, int outsz) {
    const unsigned short *u = (const unsigned short *)name_u16;
    int n = 0;
    if (!u) return -1;
    while (n < outsz - 1) {
        unsigned short w;
        if (range_unmapped(u + n, 2)) break;
        w = u[n];
        if (!w) break;
        out[n] = (w < 0x80) ? (char)w : '?';
        n++;
    }
    out[n] = 0;
    return n;
}

/* Match an ASCII name against the injected display records -> that record's packed code (fontcode<<16),
 * or 0 if none. Exact (case-insensitive) first; then the longest injected family name that is a prefix
 * of `name` at a space/end boundary (handles "Ubuntu Bold" -> "Ubuntu"). */
static unsigned r5_injected_code_for_name(const char *name) {
    uint32_t *arr; unsigned cnt, i; int best_len = -1, nlen; unsigned best_code = 0;
    if (!name || !*name || r5_inj_base <= 0) return 0;
    if (!r5s.fontrec_arr || !r5s.fontrec_cnt) return 0;
    if (range_unmapped((void *)r5s.fontrec_arr, 4) || range_unmapped((void *)r5s.fontrec_cnt, 2)) return 0;
    arr = *(uint32_t **)r5s.fontrec_arr;
    cnt = *(unsigned short *)r5s.fontrec_cnt;
    if (!arr || cnt > 8000 || cnt <= (unsigned)r5_inj_base) return 0;
    nlen = (int)strlen(name);
    for (i = (unsigned)r5_inj_base; i < cnt; i++) {         /* pass 1: exact */
        unsigned char *rec = (unsigned char *)(uintptr_t)arr[i]; const char *rn;
        if (!rec || range_unmapped(rec, 0x20)) continue;
        rn = (const char *)(uintptr_t)(*(uint32_t *)(rec + 0x10));
        if (!rn || range_unmapped(rn, 1)) continue;
        if (!strcasecmp(name, rn)) return (unsigned)(*(unsigned short *)(rec + 0x06)) << 16;
    }
    for (i = (unsigned)r5_inj_base; i < cnt; i++) {         /* pass 2: longest boundary prefix */
        unsigned char *rec = (unsigned char *)(uintptr_t)arr[i]; const char *rn; int rl;
        if (!rec || range_unmapped(rec, 0x20)) continue;
        rn = (const char *)(uintptr_t)(*(uint32_t *)(rec + 0x10));
        if (!rn || range_unmapped(rn, 1)) continue;
        rl = (int)strlen(rn);
        if (rl < 1 || rl > nlen || rl <= best_len) continue;
        if (strncasecmp(name, rn, (size_t)rl) == 0 && (name[rl] == 0 || name[rl] == ' ')) {
            best_len = rl; best_code = (unsigned)(*(unsigned short *)(rec + 0x06)) << 16;
        }
    }
    return best_code;
}

int retro5_name_to_code(void *name_u16, int *out_code, unsigned param_3) {
    int r = r5_name_to_code_orig ? r5_name_to_code_orig(name_u16, out_code, param_3) : 0;
    if (r == 0 && r5_allfonts && r5_inj_base > 0 && out_code && !range_unmapped(out_code, 4)) {
        char asc[128];
        if (r5_u16_to_ascii(name_u16, asc, (int)sizeof asc) > 0) {
            unsigned code = r5_injected_code_for_name(asc);
            if (code) {
                *out_code = (int)code;
                if (r5_trace) { char b[160]; int k = snprintf(b, sizeof b,
                    "retro5: \xc2\xa7""17.1 name->code RESCUE '%s' -> 0x%x (was collapsed)\n",
                    asc, (code >> 16) & 0xfff); if (k > 0) write(2, b, (size_t)k); }
                return 1;
            }
        }
    }
    return r;
}
static void r5_install_name_to_code_hook(void) {
    static const unsigned char g[] = {0x55,0x89,0xe5,0x81,0xec,0xc0,0x00,0x00,0x00};
    if (!(r5_docfont || r5_docfont81) || !r5_allfonts || !r5s.name_to_code_va) return;
    if (range_unmapped((void *)r5s.name_to_code_va, sizeof g)
        || memcmp((void *)r5s.name_to_code_va, g, sizeof g)) return;
    r5_name_to_code_orig = (int (*)(void *, int *, unsigned))
                           r5_make_trampoline(r5s.name_to_code_va, 9);
    if (r5_name_to_code_orig)
        patch_entry(r5s.name_to_code_va, (const char *)g, sizeof g, (void *)retro5_name_to_code);
}


/* Font-selector takeover (RETRO5_ALLFONTS): the F9 "Font Face" list builder shows an entry only if
 * record+0x1e == 0 (a printer-available-vs-display-only category byte). Normal mode leaves only the
 * current printer's font(s) at 0, so the list shows ~1; NOP the filter jne and ALL enumerated fonts
 * list. One scoped 2-byte patch — does NOT touch the 55-consumer admin flag; the shared widget-populate
 * wrapper means it fixes all font pickers at once. Per-build jne site in r5s. (FONT-RENDERING-MAP §14) */
static void r5_apply_allfonts(void) {
    unsigned char *p = (unsigned char *)r5s.sel_filter_jne;
    if (!r5_allfonts || !r5s.sel_filter_jne || range_unmapped(p, 2)) return;
    if (p[0] == r5s.sel_filter_bytes[0] && p[1] == r5s.sel_filter_bytes[1]) {
        unsigned char nop[2] = {0x90, 0x90};
        write_code(r5s.sel_filter_jne, nop, 2);
        if (r5_trace) { const char *m = "retro5: font selector unfiltered (all fonts)\n";
                        write(2, m, strlen(m)); }
    } else if (r5_trace) { const char *m = "retro5: ALLFONTS skipped (guard mismatch)\n";
                           write(2, m, strlen(m)); }
}

/* WordPerfect 8.0.0076, dynamic-X build ("build B"). .text base 0x08048000. */
static void takeoverWP80(void);          /* appearance table for this build, below */

/* ---- 8.0 mouse-wheel install (RETRO5_WHEEL, default ON) --------------------------------------
 * SAME shared handlers as 8.1 (t81_XtDispatchEvent/AddGrab/RemoveGrab/ManageChild/ManageChildren),
 * but installed by GOT interpose over 8.0's DYNAMIC Xt imports instead of static detours.  8.0 leaves
 * the *_va detour targets at 0; it fills the r5s.Xt* the shared wheel logic calls and the r5s.real_*
 * the handlers chain to (both from libXt via r5_realsym), then repoints the 5 GOT slots at our hooks.
 * GOT/PLT pairs were read live from wpbin/xwp's PLT stubs (jmp *GOT). */
static void takeoverWP80_wheel(void) {
    if (!r5_wheel) return;
    t81_wheel_config();                                  /* RETRO5_WHEEL_LINES / RETROXT_WHEEL_LINES */

    r5s.xt_dispatch_va = r5s.xt_addgrab_va = r5s.xt_removegrab_va = 0;   /* no detours on 8.0 */
    r5s.xt_managechild_va = r5s.xt_managechildren_va = 0;

    /* Xt calls the shared wheel logic makes — real libXt via r5_realsym (never our own exports). */
    r5s.XtWindowToWidget = (Widget (*)(Display *, Window))          r5_realsym("XtWindowToWidget");
    r5s.XtParent         = (Widget (*)(Widget))                    r5_realsym("XtParent");
    r5s.XtName           = (char  *(*)(Widget))                    r5_realsym("XtName");
    r5s.XtWindow         = (Window (*)(Widget))                    r5_realsym("XtWindow");
    r5s.XtHasCallbacks   = (int    (*)(Widget, char *))            r5_realsym("XtHasCallbacks");
    r5s.XtCallCallbacks  = (void   (*)(Widget, char *, XtPointer)) r5_realsym("XtCallCallbacks");
    r5s.XtVaSetValues    = (void   (*)(Widget, ...))               r5_realsym("XtVaSetValues");
    r5s.XtGetValues      = (void   (*)(Widget, ArgList, Cardinal)) r5_realsym("XtGetValues");
    r5s.XtAppNextEvent   = (void   (*)(XtAppContext, XEvent *))    r5_realsym("XtAppNextEvent");

    /* Originals the shared handlers chain to (8.0: the real dynamic Xt entrypoints). */
    r5s.real_dispatch       = (Boolean (*)(XEvent *))             r5_realsym("XtDispatchEvent");
    r5s.real_addgrab        = (void (*)(Widget, Boolean, Boolean))r5_realsym("XtAddGrab");
    r5s.real_removegrab     = (void (*)(Widget))                  r5_realsym("XtRemoveGrab");
    r5s.real_managechild    = (void (*)(Widget))                  r5_realsym("XtManageChild");
    r5s.real_managechildren = (void (*)(WidgetList, Cardinal))    r5_realsym("XtManageChildren");

    /* GOT interpose the dynamic imports -> the shared handlers (PLT/GOT read from wpbin/xwp).
     * XtAppMainLoop is interposed too: it is WP's primary event loop and its internal XtDispatchEvent
     * is libXt-private, so without replacing the loop the doc window would never see the wheel. */
    { int ok = 0;
      ok += patch_import(0x0804ff00, 0x087d8584, (void *)t81_XtDispatchEvent);   /* XtDispatchEvent  */
      ok += patch_import(0x08050bc0, 0x087d88b4, (void *)t81_XtAddGrab);         /* XtAddGrab        */
      ok += patch_import(0x0804ff10, 0x087d8588, (void *)t81_XtRemoveGrab);      /* XtRemoveGrab     */
      ok += patch_import(0x08050380, 0x087d86a4, (void *)t81_XtManageChild);     /* XtManageChild    */
      ok += patch_import(0x0804fa40, 0x087d8454, (void *)t81_XtManageChildren);  /* XtManageChildren */
      ok += patch_import(0x0804f5d0, 0x087d8338, (void *)t81_XtAppMainLoop);     /* XtAppMainLoop    */
      if (r5_trace) { char b[96]; int k = snprintf(b, sizeof b,
          "retro5: 8.0 wheel install %d/6 GOT interposes\n", ok);
          if (k > 0) write(2, b, (size_t)k); }
    }
}

static void applyWp8_0_dynX_Fixes(void) {
    /* Per-build symbol table for this (8.0 dynamic-X) binary — see FONT-RENDERING-MAP §14. */
    r5s.doc_text_va = 0x085b54e0;
    r5s.blit_site = 0;                                   /* 8.0 uses GOT interpose, not a call site */
    r5s.xcp_plt = 0x0804f2d0; r5s.xcp_got = 0x087d8278; r5s.xcp_fn = 0;   /* dynamic XCopyPlane */
    r5s.pen_x = 0x087bdd5c; r5s.pen_y = 0x087bdd60;
    r5s.metric_ptr = 0x0880878c; r5s.font_ctx = 0x08808798;
    r5s.fontrec_arr = 0x08808754; r5s.fontrec_cnt = 0x0880875a; r5s.fontrec_snap = 0x0880875c;
    r5s.glyphtab_get = (unsigned (*)(void))0x085b9840;
    r5s.sel_filter_jne = 0x085b7c98; r5s.sel_filter_bytes[0]=0x75; r5s.sel_filter_bytes[1]=0x4f;
    r5s.fontrec_cap = 0x08808758; r5s.remap_arr = 0x0880876c; r5s.remap_cap = 0x08808770;
    r5s.freecode = 0x087bdfe2; r5s.builder_va = 0x085b8500; r5s.resolver_va = 0x085b7860;
    r5s.fontcoll_build_va = 0x0852acd0;                  /* printer-font collection builder (pickers) */
    r5s.fontset_va = 0x080be820;                         /* font-set command handler (pre-collapse code) */
    r5s.font_state_ptr = 0x08812f74;                     /* -> font-state object; +0x98 = active packed code */
    r5s.name_to_code_va = 0x085b7a20;                    /* §17.1 base-space name->code resolver (bsearch) */
    /* printer subsystem (RETRO5_CUPS) — FONT-RENDERING-MAP §15/§19 */
    r5s.printer_scan_va  = 0x0852cb40;
    r5s.printer_rich_arr = 0x08803140; r5s.printer_rich_cnt = 0x08803144;
    r5s.printer_flat_arr = 0x08803120; r5s.printer_flat_cnt = 0x08803124;
    r5s.cur_printer_name = 0x08812608;

    /* Table QuickFill (Insert Table -> "Extend the pattern in the current selection"):
       guard the code-stream parser's copy at 0x08430205 (orig: call FUN_085c5dd0). */
    patch_call(0x08430205, "\xe8\xc6\x5b\x19\x00", retro5_guarded_copy);
    /* Morpher as-you-type OOB strcpy in mor_read_entry: guard the copy at 0x08259cff
       (orig: call strcpy@plt) so a wild source is skipped but valid copies still happen. */
    patch_call(0x08259cff, "\xe8\xfc\x53\xdf\xff", retro5_guarded_strcpy);
    /* PerfectExpert: the hide/cleanup handler saves the panel position via XtVaGetValues before
       its null-check; guard that call at 0x080f2a52 so a NULL widget doesn't crash and the
       toggle proceeds to create+show the panel. */
    patch_call(0x080f2a52, "\xe8\xe9\xc9\xf5\xff", retro5_guarded_XtVaGetValues);

    if (r5_skin) takeoverWP80();
    takeoverWP80_wheel();                                /* mouse-wheel scrolling (shared handlers) */
    r5_apply_allfonts();
    r5_install_injection();
    r5_install_collection_injection();
    r5_install_resolver_hook();
    r5_install_fontset_hook();          /* capture injected pick -> resolver renders it (interim; §17.1 = full) */
    r5_install_name_to_code_hook();     /* §17.1 REAL FIX: injected NAME->own code on render + reload */
    /* CUPS job routing is done at the wppx PostScript-write stage (see the file-I/O interpose), NOT
     * by touching wpexc: the live-RE (§20) proved wpexc is an idle startup daemon that is NOT on the
     * interactive print path, so bypassing its spawn was both unnecessary and the cause of the
     * "Cannot create a new process" spawn-loop. wpexc now spawns normally; and because retro5 no
     * longer starts CUPS threads in xwp at all, there is no fork-inherited lock to deadlock on. */
}

/* ---------------------------------------------------------------------------------------
 * takeoverWP80 — the APPEARANCE takeover for this build. Nothing here is logic; it is the
 * address table. Every painter it names lives above, is binary-independent, and is reused
 * verbatim by the next binary's takeover — a new build (or a helper program: xwpspell,
 * xwppmgr, xwpthes ... all Motif apps) is a new table, not new drawing code.
 *
 * Two kinds of takeover, both byte/word-guarded so a build we did not map is left alone:
 *   takeover_entry  — replace a FUNCTION's entry (`jmp ours`). For Motif's shared draw
 *                     primitives, which are static code with no symbol to interpose.
 *   takeover_method — swap a POINTER in a widget's class record, keeping the original to
 *                     call. For class methods like expose. No code is patched at all.
 * ------------------------------------------------------------------------------------ */
static void takeoverWP80(void) {
    /* Shared Motif draw primitives. Arg counts verified against this exact build by disassembly
       (highest ebp+N read); all are cdecl/plain-`ret`, so the caller's frame arrives intact. */
    static const R5Entry entries[] = {
        { 0x086bea58, "\x55\x89\xe5\x83\xec\x0c", 6, retro5_XmDrawShadows   },  /* bevels     */
        { 0x086bf600, "\x55\x89\xe5\x83\xec\x58", 6, retro5_XmDrawArrow     },  /* chevrons   */
        { 0x086bebf8, "\x55\x89\xe5\x83\xec\x6c", 6, retro5_XmDrawSeparator },  /* hairlines  */
        { 0x086bf468, "\x55\x89\xe5\x83\xec\x2c", 6, retro5_XmDrawHighlight },  /* focus ring */
        { 0x08695018, "\x55\x89\xe5\x83\xec\x0c", 6, retro5_DrawToggle      },  /* radio+check indicator */
        /* toolbar button up-scale: the XmLabel resize thunk (push $5; push w; call 0x086baea4).
         * Patched at the FUNCTION entry, not the class slot, because the inherited slot is clobbered
         * by Xt class-init. Guard pins the whole thunk incl. the worker call target. */
        { 0x086bae18, "\x55\x89\xe5\x6a\x05\xff\x75\x08\xe8\x7f\x00\x00\x00", 13, retro5_DrawnButtonResize },
    };
    /* Widget class methods. class_rec + expected current expose fn (read live off the running
       binary's class records — see MOTIF-DRAW-TAKEOVER-PLAN.md). */
    static const R5Method methods[] = {
        { 0x087cd050, 0x08649638, retro5_DrawnButtonExpose,
          (void **)&r5_orig_drawnbutton_expose, "XmDrawnButton" },   /* toolbar buttons */
        { 0x087cfb68, 0x0866d00c, retro5_PushButtonExpose,
          (void **)&r5_orig_pushbutton_expose,  "XmPushButton"  },   /* dialog buttons  */
        { 0x087d1ae8, 0x08695968, retro5_ToggleButtonExpose,
          (void **)&r5_orig_toggle_expose,      "XmToggleButton" }, /* radio + checkbox */
        { 0x087cb7d4, 0x0863beec, retro5_CascadeButtonExpose,
          (void **)&r5_orig_cascade_expose,     "XmCascadeButton" }, /* submenu items (dropdown) */
    };
    /* Text. We take over the font LOAD (XLoadQueryFont/XQueryFont) to rewrite each font's width
       metrics to our cairo advances — after which WP's OWN XTextWidth/XTextExtents return cairo
       widths for free (they sum per_char), so we do NOT hook the measure calls at all. That is the
       fix for the geometry non-convergence hang: one consistent model, so Motif's size negotiation
       settles. Then we hook the DRAW calls to render the glyphs, and XFreeFont to evict our record.
       PLT/GOT pairs from the binary's own stubs — the stub bytes are the guard. */
    static const R5Import imports[] = {
        { 0x08050900, 0x087d8804, retro5_XLoadQueryFont,   "XLoadQueryFont"   },
        { 0x08050fa0, 0x087d89ac, retro5_XQueryFont,       "XQueryFont"       },
        { 0x0804f280, 0x087d8264, retro5_XDrawString,      "XDrawString"      },
        { 0x0804f3d0, 0x087d82b8, retro5_XDrawImageString, "XDrawImageString" },
        { 0x08050840, 0x087d87d4, retro5_XDrawLine,        "XDrawLine"        },  /* menu mnemonic underline */
        { 0x08050660, 0x087d875c, retro5_XFreeFont,        "XFreeFont"        },
    };
    r5_xsyms = 0;                       /* 8.0 is dynamic-X: resolve X/Xt entry points by name */
    r5_toggle_class = 0x087d1ae8;          /* XmToggleButton class record (retro5_LabelExpose gate) */

    /* Appearance takeover — cheap (byte patches + one class-record word each), no library loads. */
    takeover_entries(entries, sizeof entries / sizeof entries[0]);
    takeover_methods(methods, sizeof methods / sizeof methods[0]);

    /* Also own the SHARED XmLabel expose (the toggle's superclass), because a toggle's arm/select
     * redraw calls it directly, off the toggle's own expose path. Its address isn't a literal: read
     * the toggle class record's superclass (offset 0) to get the XmLabel class record, and its live
     * expose slot as the guard value. retro5_LabelExpose routes toggles to us, all else to Motif. */
    if (!range_unmapped((void *)r5_toggle_class, 4)) {
        uintptr_t label_class = *(uintptr_t *)r5_toggle_class;
        if (label_class && !range_unmapped((void *)(label_class + R5_EXPOSE_OFF), 4)) {
            R5Method lm[1];
            lm[0].class_rec = label_class;
            lm[0].expect    = *(uintptr_t *)(label_class + R5_EXPOSE_OFF);
            lm[0].target    = retro5_LabelExpose;
            lm[0].saved     = (void **)&r5_orig_label_expose;
            lm[0].name      = "XmLabel";
            takeover_methods(lm, 1);
        }
    }

    /* (Toolbar button up-scaling is taken over as a FUNCTION-entry patch in `entries[]` above — the
     * XmLabel resize thunk at 0x086bae18 — because the class-record resize slot is inherited and gets
     * clobbered by Xt class-init, which silently defeated the old slot-swap takeover here.) */

    /* EWMH / _NET_WM hints (RETRO5_EWMH, default on): interpose XtRealizeWidget so every top-level
     * shell is stamped with _NET_WM_PID + WM_CLIENT_MACHINE + _NET_WM_WINDOW_TYPE once realized.
     * Independent of the appearance/text layers, so it runs here in the always-on section. 8.0 is
     * dynamic-X, so this is a GOT interpose; resolve the real fn first, then swap the slot. */
    if (r5_ewmh) {
        *(void **)&r5_real_XtRealizeWidget = r5_realsym("XtRealizeWidget");
        if (r5_real_XtRealizeWidget) {
            int ok = patch_import(0x08050df0, 0x087d8940, (void *)retro5_XtRealizeWidget);
            if (r5_trace) { const char *m = ok ? "retro5: EWMH hints enabled (XtRealizeWidget)\n"
                                               : "retro5: EWMH SKIPPED (guard mismatch)\n";
                            write(2, m, strlen(m)); }
        }
    }

    /* The cairo text layer — the ONLY expensive part of retro5. Everything here is gated behind
       RETRO5_TEXT so it can be switched off wholesale: with r5_text=0 we do NOT dlopen cairo, do
       NOT warm fontconfig, and install NO text/metrics hooks, so startup pays nothing for it and
       WP renders text with its own X path. That is the kill switch for isolating this layer from a
       startup problem without touching the appearance work above. */
    if (r5_text == 2) {                 /* DIAGNOSTIC: load the lib graph only, nothing else */
        int ok = r5_cairo_load();
        if (r5_trace) { const char *m = ok ? "retro5: DIAG loaded cairo libs (no warm, no hooks)\n"
                                            : "retro5: DIAG cairo load FAILED\n";
                        write(2, m, strlen(m)); }
    } else if (r5_text == 3) {          /* DIAGNOSTIC: load + FcInit, still no hooks */
        r5_cairo_load();
        r5_cairo_warm();
        if (r5_trace) { const char *m = "retro5: DIAG loaded + warmed fontconfig (no hooks)\n";
                        write(2, m, strlen(m)); }
    } else if (r5_text) {               /* full text layer — fully resolved before WP runs */
        r5_desktop_init();              /* file reads only */
        r5_cairo_load();                /* dlopen RTLD_NOW: cairo + deps fully bound at load */
        r5_cairo_warm();                /* FcInit + first face: no lazy fontconfig later */
        r5_resolve_reals();             /* every real X/Xt fn our hooks call — no runtime dlsym */
        takeover_imports(imports, sizeof imports / sizeof imports[0]);
        r5_text_active = 1;             /* hooks are pure now; safe to be live from WP's first call */
        /* Preload librsvg here (before WP's main), NOT lazily in an expose: a heavy dlopen inside a
         * startup expose stalls WP mid-IPC and hangs it. Only when an icon map is configured. */
        if (r5_icons_cfg && r5_icons_cfg[0]) {
            int ok = r5_rsvg_load();
            if (r5_trace) { const char *m = ok ? "retro5: librsvg loaded (SVG icons enabled)\n"
                                               : "retro5: librsvg NOT loaded (PNG icons only)\n";
                            write(2, m, strlen(m)); }
        }
        /* Document canvas font rendering (opt-in): jmp-patch WP's own glyph-blit loop draw_text_run
         * via a trampoline (so its layout body still runs) and hook XCopyPlane so each glyph is cairo-
         * drawn. Only when RETRO5_DOCFONT is set — otherwise the page is byte-for-byte WP's own. */
        if (r5_docfont && cz.icons_ok && r5s.doc_text_va) {
            static const unsigned char g[] = {0x55,0x89,0xe5,0x81,0xec,0xb0,0x00,0x00,0x00};
            int ok = 0;
            if (!memcmp((void *)r5s.doc_text_va, g, sizeof g)) {
                r5_doc_text_orig = (void (*)(void *, int, int, int, int, int))
                                   r5_make_trampoline(r5s.doc_text_va, 9);
                if (r5_doc_text_orig) {
                    patch_entry(r5s.doc_text_va, (const char *)g, sizeof g, (void *)retro5_doc_text);
                    ok = patch_import(r5s.xcp_plt, r5s.xcp_got, (void *)retro5_XCopyPlane);
                }
            }
            if (r5_trace) { char b[80]; int k = snprintf(b, sizeof b,
                "retro5: doc-font canvas render %s\n", ok ? "enabled" : "SKIPPED (guard mismatch)");
                if (k > 0) write(2, b, (size_t)k); }
        }
    }
}

/* WordPerfect 8.1 (static-X build, 8,161,760 B). DOC-FONT canvas rendering only for now — the Motif
 * appearance reskin is not yet ported (8.1 statically links Xlib/Xt, so the GOT interposition the 8.0
 * reskin relies on is impossible; it needs inline detours). Addresses from FONT-RENDERING-MAP §14.
 * draw_text_run @0x08535ca4; the glyph blit @0x08536301 is `call 0x08677d60` (XCopyPlane is a STATIC
 * function — no GOT slot). So we patch that single call site (scoped to exactly the document glyph
 * blit) rather than interposing an import, and reach the real XCopyPlane via r5_df_xcp_fn. */
static void takeoverWP81(void) {
    /* 8.1's document glyph pipeline is structurally different from 8.0 (static-X, different codegen);
     * our cairo blit hook currently destabilises it and 8.1 has its own newer renderer — so the canvas
     * cairo layer is OFF unless RETRO5_DOCFONT81 is set explicitly (experimental). 8.1's retro5 value
     * is the all-fonts selector + -admin gate + (coming) printer/reskin work, not the doc-font canvas. */
    if (r5_text && r5_docfont81) {
        r5_cairo_load();
        r5_cairo_warm();
        if (cz.icons_ok && r5s.blit_site) {
            /* 8.1 links Xlib statically (no XCopyPlane GOT). The glyph blit is one `call` to the
             * static XCopyPlane; patch just that call site -> our hook. Scoped to exactly the doc
             * glyph, so no draw_text_run entry patch and no r5_doc_active toggling are needed. */
            unsigned char *site = (unsigned char *)r5s.blit_site;
            int ok = 0;
            if (!range_unmapped(site, 5) && !memcmp(site, r5s.blit_call, 5)) {
                patch_call(r5s.blit_site, (const char *)r5s.blit_call, (void *)retro5_XCopyPlane);
                ok = (memcmp(site, r5s.blit_call, 5) != 0);   /* bytes changed => patch applied */
                if (ok) r5_doc_active = 1;                     /* call-site-scoped: always a doc glyph */
            }
            if (r5_trace) { char b[96]; int k = snprintf(b, sizeof b,
                "retro5: 8.1 doc-font canvas render %s\n", ok ? "enabled" : "SKIPPED (guard mismatch)");
                if (k > 0) write(2, b, (size_t)k); }
        }
    }
}

static void applyWp8_1_Fixes(void) {
    /* Per-build symbol table for this (8.1 static-X) binary — see FONT-RENDERING-MAP §14. */
    r5s.doc_text_va = 0x08535ca4;
    r5s.blit_site   = 0x08536301;
    r5s.blit_call[0]=0xe8; r5s.blit_call[1]=0x5a; r5s.blit_call[2]=0x1a; r5s.blit_call[3]=0x14; r5s.blit_call[4]=0x00;
    r5s.xcp_plt = 0; r5s.xcp_got = 0; r5s.xcp_fn = 0x08677d60;   /* static XCopyPlane */
    r5s.pen_x = 0x087d9f54; r5s.pen_y = 0x087d9f58;
    r5s.metric_ptr = 0x088281f8; r5s.font_ctx = 0x08828204;
    r5s.fontrec_arr = 0x088281c0; r5s.fontrec_cnt = 0x088281c6; r5s.fontrec_snap = 0x088281c8;
    r5s.glyphtab_get = (unsigned (*)(void))0x08539db8;
    r5s.sel_filter_jne = 0x08538408; r5s.sel_filter_bytes[0]=0x75; r5s.sel_filter_bytes[1]=0x4d;
    r5s.fontrec_cap = 0x088281c4; r5s.remap_arr = 0x088281d8; r5s.remap_cap = 0x088281dc;
    r5s.freecode = 0x087da1da; r5s.builder_va = 0x08538b6c; r5s.resolver_va = 0x0853803c;
    /* printer subsystem (RETRO5_CUPS) — FONT-RENDERING-MAP §15/§19 (8.1 twins of the 8.0 table) */
    r5s.printer_scan_va  = 0x084bb0c4;
    r5s.printer_rich_arr = 0x08822a38; r5s.printer_rich_cnt = 0x08822a48;
    r5s.printer_flat_arr = 0x08822a18; r5s.printer_flat_cnt = 0x08822a1c;
    r5s.cur_printer_name = 0x08832b88;
    /* 8.1 doc-font port (static-X). Motif appearance reskin not yet ported. */
    takeoverWP81();
    if (r5_wheel) takeoverWP81_full();                  /* mouse-wheel scrolling (shared handlers, static detours) */
    r5_apply_allfonts();
    r5_install_injection();
    r5_install_resolver_hook();
    /* CUPS backend on 8.1 is OUT OF SCOPE for now. Do NOT load in the constructor: the fork-deadlock
     * (see retro5_pserver_spawn) applies identically to 8.1, so an unconditional p2c_load here would
     * hang 8.1 startup. The 8.1 print-server spawn interpose (twin of the 8.0 0x0853154c/0x085c7a90
     * site) is left unwired until the 8.1 site is located. RETRO5_CUPS is therefore a no-op on 8.1. */
}

/* Add a build: hash its .text window, add one KNOWN_BINARIES row, and give it a takeoverXxx()
 * that is JUST a table like the one above. Static-X hosts additionally point r5_xsyms at their
 * own R5XSyms table of absolute X/Xt addresses; the painters do not change. */

/* ======================================================================================= *
 *  Dispatch: identify the host binary, run its fixes
 * ======================================================================================= */

/* Identifying hash = FNV-1a/32 over a fixed .text window that contains no patch sites and is
 * untouched by the DT_NEEDED retarget, so it is stable whatever else was edited. */
#define HASH_VA  0x08100000u
#define HASH_LEN 0x00010000u

struct known_binary { uint32_t hash; const char *name; void (*apply)(void); };
static const struct known_binary KNOWN_BINARIES[] = {
    { 0x12d07fceu, "WordPerfect 8.0.0076 (dynamic-X)", applyWp8_0_dynX_Fixes },
    { 0x5f86b242u, "WordPerfect 8.1 (static-X)",       applyWp8_1_Fixes      },
    /* { 0x........, "WordPerfect 8.0 (static-X, 8.16 MB)", applyWp8_0_staticX_Fixes }, */
};

static const struct known_binary *matchBinaryHash(void) {
    if (range_unmapped((const void *)HASH_VA, HASH_LEN)) return 0;   /* not a WP8-shaped binary */
    uint32_t h = fnv1a((const void *)HASH_VA, HASH_LEN);
    for (size_t i = 0; i < sizeof KNOWN_BINARIES / sizeof KNOWN_BINARIES[0]; i++)
        if (KNOWN_BINARIES[i].hash == h) return &KNOWN_BINARIES[i];
    return 0;                                                        /* unknown -> no fixes */
}

__attribute__((constructor))
static void findBinaryFixes(void) {
    const struct known_binary *b = matchBinaryHash();
    const char *skin = getenv("RETRO5_SKIN");
    const char *text = getenv("RETRO5_TEXT");
    const char *uiscale = getenv("RETRO5_UI_SCALE");
    if (uiscale && uiscale[0]) {                         /* override the dpi-derived UI scale */
        double v = atof(uiscale);
        if (v >= 1.0 && v <= 3.0) r5_ui_scale_env = v;
    }
    if (skin && skin[0] == '0') r5_skin = 0;             /* stock Motif drawing, for A/B */
    if (text) {
        if (text[0] == '0')             r5_text = 0;     /* text layer off */
        else if (!strcmp(text, "load")) r5_text = 2;     /* diagnostic: load cairo libs only */
        else if (!strcmp(text, "warm")) r5_text = 3;     /* diagnostic: load + FcInit, no hooks */
    }
    if (getenv("RETRO5_TRACE")) r5_trace = 1;
    if (getenv("RETRO5_ICON_DUMP")) r5_icon_dump = 1;    /* log each toolbar icon's content hash */
    r5_icons_cfg = getenv("RETRO5_ICONS");               /* hash->file replacement map (NULL = off) */
    { const char *d = getenv("RETRO5_DOCFONT");          /* 0 = off; 1 = document canvas; 2 = + chrome */
      if (d && *d) { int v = atoi(d); r5_docfont = v <= 0 ? 0 : (v >= 2 ? 2 : 1); } }
    { const char *e = getenv("RETRO5_DOCFONT81"); if (e && *e && e[0] != '0') r5_docfont81 = 1; }  /* EXPERIMENTAL 8.1 canvas */
    { const char *e = getenv("RETRO5_ALLFONTS");  if (e && *e && e[0] != '0') r5_allfonts = 1; }   /* unfilter + inject system fonts */
    { const char *e = getenv("RETRO5_MEMBERS");   if (e && *e) r5_member_limit = atoi(e); }        /* §17.1 de-risk: cap appended member faces (0 = all) */
    { const char *e = getenv("RETRO5_FONTCOLL");  r5_fontcoll = e ? (*e && e[0] != '0') : r5_allfonts; }   /* append system faces to the printer-font collection (the picker list source); defaults to ALLFONTS, set 0 to opt out */
    { const char *e = getenv("RETRO5_EWMH");       if (e && e[0] == '0') r5_ewmh = 0; }             /* _NET_WM hints on toplevels (default on) */
    { const char *e = getenv("RETRO5_CUPS");       if (e && *e && e[0] != '0') r5_cups = 1; }       /* back WP's printer subsystem with CUPS */
    { const char *e = getenv("RETRO5_WHEEL");      if (e && e[0] == '0') r5_wheel = 0; }             /* mouse-wheel scrolling (default ON) */
    { const char *p = getenv("RETRO5_DOCFONT_PX"); if (p && *p) r5_doc_px = atof(p); }  /* size tuning */
    if (getenv("RETRO5_DEBUG")) {
        const char *p = b ? "retro5: applying fixes for " : "retro5: no fixes (unrecognised binary)\n";
        write(2, p, strlen(p));
        if (b) { write(2, b->name, strlen(b->name)); write(2, "\n", 1); }
    }
    if (b) b->apply();
}
