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
static int range_unmapped(const void *p, size_t n) {
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
static void patch_entry(uintptr_t va, const void *guard, unsigned glen, void *target) {
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
#define R5_COL_HAIRLINE 0xd2d6dbu   /* etched rules, separators, group boxes                */
#define R5_COL_GLYPH    0x5a6270u   /* arrow chevrons — soft slate, never black             */
#define R5_COL_PRESS    0xccd4e0u   /* pressed/latched button FACE — only ownable from expose */

enum { R5_GC_EDGE, R5_GC_SUNK, R5_GC_SUNK_IN, R5_GC_HAIRLINE, R5_GC_GLYPH, R5_GC_PRESS, R5_GC_N };
static const uint32_t R5_RGB[R5_GC_N] = {
    R5_COL_EDGE, R5_COL_SUNK, R5_COL_SUNK_IN, R5_COL_HAIRLINE, R5_COL_GLYPH, R5_COL_PRESS
};

static int r5_skin = 1;             /* RETRO5_SKIN=0 -> leave Motif's drawing alone */
static int r5_trace;                /* RETRO5_TRACE=1 -> log every draw call + its widget */

/* ---- the X/Xt call layer, bound two different ways ----
 * The painters below are binary-independent, but HOW they reach X is not. A dynamically-linked host
 * (8.0: libX11/libXt are DT_NEEDED) resolves the entry points by NAME. The near-static WP builds
 * link Xlib straight into the executable, where there is no dynamic symbol to look up — so those
 * binaries hand us a table of absolute VAs instead, and everything above this line stays identical.
 * That is the whole reason this is a vtable and not a pile of direct calls. */
typedef struct {
    uintptr_t CreateGC, SetLineAttributes, DrawSegments, DrawPoints, DrawLines,
              FillRectangle, AllocColor, GetGCValues, QueryColor, GetGeometry,
              CopyArea, CopyPlane, XtDisplayOfObject, XtWindowOfObject;
} R5XSyms;

static struct {
    int      ready;                 /* 0 = untried, 1 = usable, -1 = unavailable */
    GC     (*CreateGC)(Display *, Drawable, unsigned long, XGCValues *);
    int    (*SetLineAttributes)(Display *, GC, unsigned, int, int, int);
    int    (*DrawSegments)(Display *, Drawable, GC, XSegment *, int);
    int    (*DrawPoints)(Display *, Drawable, GC, XPoint *, int, int);
    int    (*DrawLines)(Display *, Drawable, GC, XPoint *, int, int);
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
    Display *(*XtDisplayOfObject)(void *);
    Window   (*XtWindowOfObject)(void *);
} r5x;

/* Set by the per-binary takeover when the host is static; NULL means "resolve by name". */
static const R5XSyms *r5_xsyms;

/* member <- dlsym("<sym>")            (dynamic hosts)
 * member <- absolute VA from the binary's own table   (static hosts) */
#define R5_SYM(memb, sym) (*(void **)&r5x.memb = dlsym(RTLD_DEFAULT, sym), r5x.memb != 0)
#define R5_ADDR(memb)     (r5_xsyms->memb && !range_unmapped((void *)r5_xsyms->memb, 1) \
                           ? (*(void **)&r5x.memb = (void *)r5_xsyms->memb, 1) : 0)

static int r5_xlib(void) {
    if (r5x.ready) return r5x.ready > 0;
    r5x.ready = -1;                                       /* try once; never retry on failure */
    if (r5_xsyms) {                                       /* static host: absolute addresses */
        if (R5_ADDR(CreateGC) && R5_ADDR(SetLineAttributes) && R5_ADDR(DrawSegments) &&
            R5_ADDR(DrawPoints) && R5_ADDR(DrawLines) && R5_ADDR(FillRectangle) &&
            R5_ADDR(AllocColor) && R5_ADDR(GetGCValues) && R5_ADDR(QueryColor) &&
            R5_ADDR(GetGeometry) && R5_ADDR(CopyArea) && R5_ADDR(CopyPlane) &&
            R5_ADDR(XtDisplayOfObject) && R5_ADDR(XtWindowOfObject))
            r5x.ready = 1;
    } else {                                              /* dynamic host: resolve by name */
        if (R5_SYM(CreateGC,          "XCreateGC")          &&
            R5_SYM(SetLineAttributes, "XSetLineAttributes") &&
            R5_SYM(DrawSegments,      "XDrawSegments")      &&
            R5_SYM(DrawPoints,        "XDrawPoints")        &&
            R5_SYM(DrawLines,         "XDrawLines")         &&
            R5_SYM(FillRectangle,     "XFillRectangle")     &&
            R5_SYM(AllocColor,        "XAllocColor")        &&
            R5_SYM(GetGCValues,       "XGetGCValues")       &&
            R5_SYM(QueryColor,        "XQueryColor")        &&
            R5_SYM(GetGeometry,       "XGetGeometry")       &&
            R5_SYM(CopyArea,          "XCopyArea")          &&
            R5_SYM(CopyPlane,         "XCopyPlane")         &&
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
static const char *r5_widget_class(void *w) {
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
    if (thickness <= 0 || w <= 0 || h <= 0) return;       /* Motif asks for nothing -> draw nothing */
    if (!dpy || !d) return;
    if (!r5_xlib()) return;

    sunk = r5_sunken(dpy, top_gc, bottom_gc, type);
    cls  = r5_widget_class(r5_caller_widget());           /* who is being painted? */

    if (r5_trace) {
        char b[200];
        int n = snprintf(b, sizeof b,
                         "shadow %-22s w=%3d h=%3d thick=%d type=%u sunk=%2d\n",
                         cls ? cls : "(unknown)", w, h, thickness, type, sunk);
        if (n > 0) write(2, b, (size_t)n);
    }

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

/* _XmDrawSeparator — the etched double-rule between menu groups and dialog sections becomes a
 * single hairline, inset from the ends so it reads as a divider rather than a border.
 * cdecl (dpy, d, top_gc, bottom_gc, sep_gc, x, y, w, h, thickness, margin, orientation, type)
 * — 13 args. orientation: XmVERTICAL=0, XmHORIZONTAL=1. */
void retro5_XmDrawSeparator(Display *dpy, Drawable d, GC top_gc, GC bottom_gc, GC sep_gc,
                            int x, int y, int w, int h, int thickness, int margin,
                            unsigned char orientation, unsigned char type) {
    XSegment s;
    GC gc;
    (void)top_gc; (void)bottom_gc; (void)sep_gc; (void)thickness; (void)type;
    if (w <= 0 || h <= 0 || !dpy || !d) return;
    if (!(gc = r5_pick(dpy, d, R5_GC_HAIRLINE))) return;

    if (orientation == 1) {                               /* horizontal rule */
        int cy = y + h / 2;
        s.x1 = x + margin; s.y1 = cy; s.x2 = x + w - 1 - margin; s.y2 = cy;
    } else {                                              /* vertical rule */
        int cx = x + w / 2;
        s.x1 = cx; s.y1 = y + margin; s.x2 = cx; s.y2 = y + h - 1 - margin;
    }
    r5x.DrawSegments(dpy, d, gc, &s, 1);
}

/* _XmDrawHighlight — the focus/arm border. Motif draws a heavy solid box (highlightThickness deep,
 * usually black); ours is a 1px rounded ring.
 *
 * We draw with the GC MOTIF PASSED, not a palette GC of our own, and that is load-bearing: Motif
 * *erases* a highlight by calling this same function again with the widget's BACKGROUND gc. Impose
 * our own color and every unfocused widget keeps a permanent ring. Honoring hl_gc preserves the
 * draw/erase pairing exactly — the erase repaints the identical rounded path in the background
 * color — and leaves the ring's COLOR where it belongs: retroXt's `highlightColor` resource, which
 * feeds this GC. cdecl (dpy, d, gc, x, y, w, h, thickness, line_style) — 9 args. */
void retro5_XmDrawHighlight(Display *dpy, Drawable d, GC hl_gc,
                            int x, int y, int w, int h, int thickness, int line_style) {
    (void)line_style;
    if (thickness <= 0 || w <= 0 || h <= 0) return;       /* nothing asked for -> nothing drawn */
    if (!dpy || !d || !hl_gc) return;
    if (!r5_xlib()) return;
    r5_round_rect(dpy, d, hl_gc, x, y, w, h);
}

/* ======================================================================================= *
 *  Font aliasing — pointing WP's X core fonts at the system's
 * ======================================================================================= *
 * WP is pure X-core-font: it asks for fonts by XLFD (XLoadQueryFont / XListFonts) and measures
 * them with XTextWidth. No Xft, no fontconfig — it predates both. Rather than rewrite the text
 * rendering (which would mean owning metrics too, or every layout in the app shifts), we sit on the
 * SELECTION calls and rewrite the font NAME. WP still measures exactly the font it draws, so
 * spacing stays self-consistent — the font simply becomes a modern one.
 *
 * The mapping is a table, overridable by a config file so a skin can retune fonts without a
 * rebuild:  ~/.config/retro5/fonts.conf  (or $RETRO5_FONTS), one rule per line:
 *
 *     # pattern                        replacement
 *     -*-helvetica-*                   -*-dejavu sans-medium-r-normal--*-*-*-*-p-*-iso8859-1
 *
 * `*` matches any run of characters; first rule that matches wins. An alias that fails to load
 * falls back to the font WP originally asked for — a bad config can make the UI ugly, never
 * textless. (WP's bundled character-set bitmaps, shlib10/fonts/wc*.pcf, are deliberately NOT
 * aliased by default: they carry WP's own glyph encodings, and substituting them would mangle
 * symbols rather than modernise them.) */

#define R5_FONT_RULES 32
static struct { char pat[128], repl[192]; } r5_fonts[R5_FONT_RULES];
static int r5_font_n;
static int r5_font_loaded;

/* glob with a single wildcard character: '*' matches any run (including empty). */
static int r5_glob(const char *pat, const char *s) {
    for (; *pat; pat++, s++) {
        if (*pat == '*') {
            if (!pat[1]) return 1;                        /* trailing * matches the rest */
            for (; *s; s++)
                if (r5_glob(pat + 1, s)) return 1;
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

/* Read the config file, if there is one. Format: `pattern<whitespace>replacement`, # comments. */
static void r5_font_config(void) {
    char path[512], line[384];
    const char *env = getenv("RETRO5_FONTS");
    const char *home = getenv("HOME");
    FILE *f;

    if (env && *env) {
        strncpy(path, env, sizeof path - 1); path[sizeof path - 1] = 0;
    } else if (home) {
        snprintf(path, sizeof path, "%s/.config/retro5/fonts.conf", home);
    } else {
        return;
    }
    if (!(f = fopen(path, "r"))) return;
    while (fgets(line, sizeof line, f)) {
        char *p = line, *pat, *repl, *e;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || !*p) continue;
        pat = p;
        while (*p && *p != ' ' && *p != '\t') p++;        /* pattern ends at whitespace */
        if (!*p) continue;
        *p++ = 0;
        while (*p == ' ' || *p == '\t') p++;
        repl = p;
        e = repl + strlen(repl);
        while (e > repl && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = 0;
        if (*repl) r5_font_add(pat, repl);
    }
    fclose(f);
    if (r5_trace) {
        char b[160];
        int n = snprintf(b, sizeof b, "retro5: loaded %d font rule(s) from %s\n", r5_font_n, path);
        if (n > 0) write(2, b, (size_t)n);
    }
}

/* No built-in rules, on purpose.
 *
 * The tempting default — alias helvetica -> DejaVu — cannot work, and it is worth writing down why
 * so nobody adds it back: a modern X server has NO FreeType core-font backend and ships no
 * fonts.dir for the system TTFs, so DejaVu is simply not among the ~1300 core fonts it will serve.
 * The core font path contains legacy bitmaps and URW Type1 clones and nothing else. Aliasing one
 * XLFD to another can therefore only swap a 1990s face for another 1990s face.
 *
 * Reaching the actual system fonts means bypassing core fonts entirely and drawing text with
 * cairo/fontconfig — which also means owning the METRICS calls (XTextWidth, XTextExtents,
 * XmbTextExtents) in the same breath, because WP measures with one call and draws with another and
 * the two must agree or every layout in the app shifts. That is the next step; this table is the
 * mapping it will consume, keyed the same way, with families instead of XLFDs.
 *
 * Until then the table stays empty by default and the config file is the only source of rules — so
 * the font path is honest: it changes nothing unless you tell it to. */
static void r5_font_init(void) {
    if (r5_font_loaded) return;
    r5_font_loaded = 1;
    r5_font_config();
}

static const char *r5_font_alias(const char *name) {
    int i;
    if (!name || !*name) return 0;
    r5_font_init();
    for (i = 0; i < r5_font_n; i++)
        if (r5_glob(r5_fonts[i].pat, name)) return r5_fonts[i].repl;
    return 0;
}

/* The interposed selection calls. Both keep WP's original name as the fallback, so a font we
 * cannot load costs us the restyle, never the text. */
static XFontStruct *(*r5_real_LoadQueryFont)(Display *, const char *);
static char **(*r5_real_ListFonts)(Display *, const char *, int, int *);

XFontStruct *retro5_XLoadQueryFont(Display *dpy, const char *name) {
    const char *alias;
    XFontStruct *fs;
    if (!r5_real_LoadQueryFont) *(void **)&r5_real_LoadQueryFont =
                                    dlsym(RTLD_DEFAULT, "XLoadQueryFont");
    if (!r5_real_LoadQueryFont) return 0;
    if (r5_skin && (alias = r5_font_alias(name)) != 0) {
        if ((fs = r5_real_LoadQueryFont(dpy, alias)) != 0) return fs;
        if (r5_trace) {
            char b[256];
            int n = snprintf(b, sizeof b, "retro5: font alias failed, keeping %s\n", name);
            if (n > 0) write(2, b, (size_t)n);
        }
    }
    return r5_real_LoadQueryFont(dpy, name);              /* WP's own choice, always available */
}

char **retro5_XListFonts(Display *dpy, const char *pattern, int maxnames, int *count) {
    const char *alias;
    char **r;
    if (!r5_real_ListFonts) *(void **)&r5_real_ListFonts = dlsym(RTLD_DEFAULT, "XListFonts");
    if (!r5_real_ListFonts) { if (count) *count = 0; return 0; }
    if (r5_skin && (alias = r5_font_alias(pattern)) != 0) {
        if ((r = r5_real_ListFonts(dpy, alias, maxnames, count)) != 0 && count && *count > 0)
            return r;
    }
    return r5_real_ListFonts(dpy, pattern, maxnames, count);
}

/* ---- the two reusable takeover tables ----
 * A per-binary takeoverXxx() is nothing but these two tables plus (for static hosts) an R5XSyms.
 * Everything they point at is shared, binary-independent code. */
typedef struct {
    uintptr_t   va;           /* function entry to replace          */
    const char *guard;        /* bytes that must be there (the build fingerprint) */
    unsigned    glen;
    void       *target;       /* our replacement                    */
} R5Entry;

typedef struct {
    uintptr_t   plt;          /* the host's PLT stub for this import */
    uintptr_t   got;          /* its GOT slot (proved by the stub)   */
    void       *target;       /* our replacement                     */
    const char *name;         /* for RETRO5_DEBUG                    */
} R5Import;

typedef struct {
    uintptr_t   class_rec;    /* widget class record                */
    uintptr_t   expect;       /* expose fn currently in the slot    */
    void       *target;       /* our replacement                    */
    void      **saved;        /* where to stash the original        */
    const char *name;         /* for RETRO5_DEBUG                   */
} R5Method;

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
static void retro5_round_widget(void *w) {
    Display *dpy;
    Window win, root;
    unsigned long bg;
    unsigned int ww, hh, bw, dep;
    int wx, wy;
    void *parent;
    GC gc;
    XPoint p[12];
    int i = 0, x1, y1;

    if (!r5_skin || !w || !r5_xlib()) return;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return;
    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bw, &dep)) return;
    if (ww < 6 || hh < 6) return;

    parent = *(void **)((char *)w + 8);                   /* core.parent */
    if (!parent || range_unmapped(parent, 12) || *(void **)parent != parent) return;
    if (!r5_bg_pixel(parent, &bg)) return;
    if (!(gc = r5_gc_for_pixel(dpy, win, bg))) return;

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
    r5x.DrawPoints(dpy, win, gc, p, i, CoordModeOrigin);
}

/* Read several resources off a widget in one XtGetValues. */
static void r5_get(void *w, R5Arg *args, unsigned n) {
    if (!g_XtGetValues) g_XtGetValues = (void (*)(void *, R5Arg *, unsigned))
                                        dlsym(RTLD_DEFAULT, "XtGetValues");
    if (g_XtGetValues) g_XtGetValues(w, args, n);
}

/* ---- the icon seam ----
 * Every button icon in the app now flows through here on its way to the screen, which is the
 * whole point of owning expose: return a different Pixmap and the button wears a different icon.
 * A future skin can key off the widget name (XtName) or the original pixmap's id to substitute
 * rendered SVG, a hi-dpi bitmap, whatever — nothing else in the paint path has to change.
 * Returning 0 means "use WP's own pixmap", which is what we do today. */
static Pixmap r5_icon_for(void *w, Pixmap original) {
    (void)w; (void)original;
    return 0;
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
    int wx, wy, px, py, sunk;
    unsigned int ww, hh, bw, dep, pw, ph, pbw, pdep;
    GC face;
    R5Arg args[3];

    if (!r5_skin || !w || !r5_xlib()) return 0;
    dpy = r5x.XtDisplayOfObject(w);
    win = r5x.XtWindowOfObject(w);
    if (!dpy || !win) return 0;

    args[0].name = (char *)"labelPixmap"; args[0].value = (long)&pm;
    args[1].name = (char *)"background";  args[1].value = (long)&bg;
    args[2].name = (char *)"shadowType";  args[2].value = (long)&shadow_type;
    r5_get(w, args, 3);

    if ((custom = r5_icon_for(w, pm)) != 0) pm = custom;
    if (!pm) return 0;                                    /* no pixmap -> let Motif draw it */

    if (!r5x.GetGeometry(dpy, win, &root, &wx, &wy, &ww, &hh, &bw, &dep)) return 0;
    if (!r5x.GetGeometry(dpy, pm, &root, &px, &py, &pw, &ph, &pbw, &pdep)) return 0;
    if (ww < 4 || hh < 4) return 0;

    sunk = (shadow_type == R5_SHADOW_IN);

    /* 1. face. Filling is safe here (unlike inside _XmDrawShadows) precisely because we own the
     *    order: the icon has not been drawn yet — we draw it, below, on top. */
    face = sunk ? r5_pick(dpy, win, R5_GC_PRESS) : r5_gc_for_pixel(dpy, win, bg);
    if (face) r5x.FillRectangle(dpy, win, face, 0, 0, ww, hh);

    /* 2. border: a pressed button gets the inset frame; at rest a toolbar button wears none. */
    if (sunk)            r5_inset(dpy, win, 0, 0, (int)ww, (int)hh);
    else if (!flat_at_rest) {
        GC e = r5_pick(dpy, win, R5_GC_EDGE);
        if (e) r5_round_rect(dpy, win, e, 0, 0, (int)ww, (int)hh);
    }

    /* 3. the icon, centered; nudged a pixel down-right while pressed, so the press is felt. */
    px = ((int)ww - (int)pw) / 2 + (sunk ? 1 : 0);
    py = ((int)hh - (int)ph) / 2 + (sunk ? 1 : 0);
    if (pdep == 1) {                                      /* bitmap: stencil it in the fg color */
        GC g = r5_pick(dpy, win, R5_GC_GLYPH);
        if (g) r5x.CopyPlane(dpy, pm, win, g, 0, 0, pw, ph, px, py, 1);
    } else if (pdep == dep) {
        GC g = r5_gc_for_pixel(dpy, win, bg);
        if (g) r5x.CopyArea(dpy, pm, win, g, 0, 0, pw, ph, px, py);
    } else {
        return 0;                                         /* depth we don't understand -> defer */
    }

    retro5_round_widget(w);                               /* carve the corners, last */
    return 1;
}

/* The class expose methods we take over. Each keeps its original, used only as the fallback for a
 * button we cannot paint (no pixmap: a text label, or content drawn from an expose callback).
 * Signature is Xt's XtExposeProc: (Widget, XEvent *, Region). */
static void (*r5_orig_drawnbutton_expose)(void *, XEvent *, Region);
static void (*r5_orig_pushbutton_expose)(void *, XEvent *, Region);

void retro5_DrawnButtonExpose(void *w, XEvent *ev, Region region) {
    if (retro5_paint_button(w, 1)) return;                /* toolbar: frameless at rest */
    if (r5_orig_drawnbutton_expose) r5_orig_drawnbutton_expose(w, ev, region);
    retro5_round_widget(w);
}
void retro5_PushButtonExpose(void *w, XEvent *ev, Region region) {
    if (retro5_paint_button(w, 0)) return;                /* dialog buttons keep their frame */
    if (r5_orig_pushbutton_expose) r5_orig_pushbutton_expose(w, ev, region);
    retro5_round_widget(w);
}

/* ======================================================================================= *
 *  Per-binary fix routines — each concentrated, self-contained, and obvious
 * ======================================================================================= */

/* WordPerfect 8.0.0076, dynamic-X build ("build B"). .text base 0x08048000. */
static void takeoverWP80(void);          /* appearance table for this build, below */

static void applyWp8_0_dynX_Fixes(void) {
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
    };
    /* Widget class methods. class_rec + expected current expose fn (read live off the running
       binary's class records — see MOTIF-DRAW-TAKEOVER-PLAN.md). */
    static const R5Method methods[] = {
        { 0x087cd050, 0x08649638, retro5_DrawnButtonExpose,
          (void **)&r5_orig_drawnbutton_expose, "XmDrawnButton" },   /* toolbar buttons */
        { 0x087cfb68, 0x0866d00c, retro5_PushButtonExpose,
          (void **)&r5_orig_pushbutton_expose,  "XmPushButton"  },   /* dialog buttons  */
    };
    /* Font selection. WP asks X for fonts by name; we rewrite the name (see r5_font_alias).
       PLT/GOT pairs from the binary's own stubs — the stub bytes are the guard. */
    static const R5Import imports[] = {
        { 0x08050900, 0x087d8804, retro5_XLoadQueryFont, "XLoadQueryFont" },
        { 0x08050620, 0x087d874c, retro5_XListFonts,     "XListFonts"     },
    };
    r5_xsyms = 0;                       /* 8.0 is dynamic-X: resolve X/Xt entry points by name */
    takeover_entries(entries, sizeof entries / sizeof entries[0]);
    takeover_methods(methods, sizeof methods / sizeof methods[0]);
    takeover_imports(imports, sizeof imports / sizeof imports[0]);
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
    if (skin && skin[0] == '0') r5_skin = 0;             /* stock Motif drawing, for A/B */
    if (getenv("RETRO5_TRACE")) r5_trace = 1;
    if (getenv("RETRO5_DEBUG")) {
        const char *p = b ? "retro5: applying fixes for " : "retro5: no fixes (unrecognised binary)\n";
        write(2, p, strlen(p));
        if (b) { write(2, b->name, strlen(b->name)); write(2, "\n", 1); }
    }
    if (b) b->apply();
}
