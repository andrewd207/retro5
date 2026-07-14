/* takeover81.c — the WordPerfect 8.1 takeover for the unified retro5.so.
 * SPDX-License-Identifier: MIT
 *
 * THE UNIFIED MODEL
 *   retro5.so holds ONE shared reskin/feature body.  A build differs only in how that body is
 *   INSTALLED over the host:
 *       8.0 (dynamic-X)  — the linker/GOT interposes the dynamic Xt/X11 symbols (see patch5.c).
 *       8.1 (static-X)   — xwp links Xt/X11 STATICALLY, so there is no dynamic symbol to interpose;
 *                          we install inline DETOURS over the fixed absolute prologues instead.
 *   This file is the 8.1 static-detour installer.  It is a faithful port of the proven 8.0 Xt
 *   interposer installer/retroXt.c, adapted to the detour model and driven by the shared R5Syms
 *   table so the very same wheel logic runs on both builds.
 *
 * WHAT THIS FIRST VERSION PORTS  (from retroXt.c)
 *   • MOUSE-WHEEL SCROLLING (the 8.1 regression this unification is meant to restore):
 *       - t81_XtDispatchEvent  detours XtDispatchEvent (0x08657ab0): on Button4/5 press, while no
 *         menu is posted, find the target scrollbar (t81_wheel_target) and drive it (t81_do_wheel),
 *         swallowing BOTH the press and release so an open combo drop-list is not dismissed.
 *       - t81_XtAddGrab / t81_XtRemoveGrab detour the grab calls (0x08657d00 / 0x08657da0) to track
 *         XmMenuShell modal grabs into a menu-depth counter, so the wheel stands down while a menu
 *         is up (driving a scrollbar during that modal grab deadlocks the app).
 *   • DOCUMENT-SCROLLBAR DISCOVERY (t81_docsb / t81_docshell / t81_tallsb): fed by detours on
 *     XtManageChild / XtManageChildren (0x0865e040 / 0x0865df30), keyed on the "scrollbar0" name
 *     with a tallest-vertical-scrollbar fallback — exactly retroXt.c's rx_note_widget inventory,
 *     trimmed to just what the wheel's document fallback needs.
 *
 * WHY R5Syms-DRIVEN
 *   The wheel logic (t81_wheel_target / t81_do_wheel) never names a concrete Xt function; it calls
 *   through r5s.XtWindowToWidget / r5s.XtParent / r5s.XtVaGetValues / … .  takeoverWP81_full() fills
 *   those with xwp's STATIC addresses; the 8.0 takeover fills the same fields with dlsym'd dynamic
 *   pointers.  One body, two installs.
 *
 * SAFETY
 *   Every detour target is mincore-probed (range_unmapped) and byte-guarded by its own current
 *   prologue before we write; the whole-binary fingerprint gate in patch5.c (matchBinaryHash) has
 *   already confirmed this is the mapped 8.1 build before applyWp8_1_Fixes → takeoverWP81_full runs.
 *
 * STATUS: INTEGRATED.  This file is compiled into retro5.so (src/ glob) and its handlers are ALSO
 * the 8.0 wheel path — patch5.c GOT-interposes t81_XtDispatchEvent/AddGrab/RemoveGrab/ManageChild/
 * ManageChildren over 8.0's dynamic Xt imports, and takeoverWP81_full() installs the same handlers as
 * static detours on 8.1.  Both fill r5s.real_* with the originals the handlers chain to.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>           /* vsnprintf */
#include <stdlib.h>          /* getenv, atoi */
#include <string.h>          /* memcpy, strcmp, strlen */
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <X11/Intrinsic.h>   /* Widget / XEvent / Boolean / Cardinal / WidgetList / Dimension … */

#include "r5syms.h"          /* R5Syms + the shared instance r5s (holds the wheel/Xt fields) */
#include "r5core.h"          /* range_unmapped, patch_entry, r5_make_trampoline, r5_trace */

/* r5_widget_class() is the shared, fault-safe "class name of a widget" helper.  It is currently
 * `static` in patch5.c (see ~line 410); INTEGRATION MUST un-static it (and add a prototype to
 * r5core.h) so this extern resolves at link time.  We reuse it rather than re-deriving the class
 * name so both builds classify widgets identically. */
extern const char *r5_widget_class(void *w);

/* ============================================================================================ *
 *  Minimal inline-detour installer (reuses the shared primitives — no private write_code / arena)
 * ============================================================================================ *
 * Per target:  trampoline = r5_make_trampoline(va, steal)  → [relocated prologue][jmp va+steal]
 *              entry       = patch_entry(va, <current bytes>, steal, hook)  → `jmp hook` (+nop pad)
 * We capture the target's CURRENT prologue and hand it to patch_entry as the guard, so patch_entry's
 * byte-guard always matches (the whole-binary fingerprint is what actually pins the build) while we
 * still go through the one shared, page-protecting code writer.  patch81.py has proven every WP 8.1
 * prologue here is position-independent, so the verbatim byte copy in the trampoline is safe.
 * NOTE (build-model): this is the "minimal local equivalent" the task allows.  It leans on the
 * shared r5_make_trampoline + patch_entry rather than duplicating detour81.c's arena/write logic. */
static int t81_detour(uintptr_t va, unsigned steal, void *hook, void **orig)
{
    unsigned char guard[16];
    void *tr;
    if (!va || steal < 5 || steal > sizeof guard) return 0;
    if (range_unmapped((const void *)va, steal)) return 0;
    memcpy(guard, (const void *)va, steal);          /* exact current prologue = the guard */
    tr = r5_make_trampoline(va, steal);              /* build BEFORE patching (copies originals) */
    if (!tr) return 0;
    if (orig) *orig = tr;
    patch_entry(va, (const char *)guard, steal, hook);   /* writes `jmp hook` over the entry */
    return 1;
}

/* ---- diagnostics (RETRO5_TRACE): FILE*-free, like retroXt.c's logger ------------------------ *
 * retro5 exports a libc5 FILE layout that corrupts glibc FILE* output, so format into a buffer and
 * emit with the raw write(2) syscall (retro5 does not wrap syscall()).  Gated by the shared r5_trace. */
static void t81_log(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    int n;
    if (!r5_trace) return;
    memcpy(buf, "[retro5/wheel81] ", 17);
    va_start(ap, fmt);
    n = vsnprintf(buf + 17, sizeof buf - 19, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof buf - 19) n = sizeof buf - 19;
    buf[17 + n] = '\n';
    { const char *p = buf; size_t left = (size_t)n + 18;
      while (left) { long w = syscall(SYS_write, 2, p, left); if (w <= 0) break; p += w; left -= (size_t)w; } }
}

/* ============================================================================================ *
 *  Chaining to the ORIGINAL bodies
 * ============================================================================================ *
 * The handlers below chain to r5s.real_* rather than any file-local trampoline, so ONE handler body
 * serves both builds: on 8.1 takeoverWP81_full points r5s.real_* at the detour trampolines it saves;
 * on 8.0 patch5.c points them at the r5_realsym'd dynamic Xt entrypoints it GOT-interposes over. */

/* ============================================================================================ *
 *  Shared wheel state + helpers (ported from retroXt.c rx_*).  All Xt calls go through r5s.*.
 * ============================================================================================ */
static Widget    t81_docsb;             /* "scrollbar0" — WP's document vertical scrollbar */
static Widget    t81_docshell;          /* top-level shell that owns the document          */
static Widget    t81_tallsb;            /* fallback: tallest vertical scrollbar seen        */
static Dimension t81_tallh;
static int       t81_menu_depth;        /* >0 while a Motif (XmMenuShell) menu is posted    */
static int       t81_wheel_lines = 3;   /* text lines per wheel notch (RETROXT/RETRO5_WHEEL_LINES) */

/* class name of a widget OR gadget, via the shared fault-safe helper (NULL-safe). */
static const char *t81_class(Widget w)
{
    const char *c = r5_widget_class((void *)w);
    return c ? c : "";
}

/* True if w is a shell — its class name ends in "Shell" (XmMenuShell, XmDialogShell, …). */
static int t81_is_shell(Widget w)
{
    const char *c = t81_class(w);
    size_t n = strlen(c);
    return n >= 5 && strcmp(c + n - 5, "Shell") == 0;
}

/* Nearest enclosing shell of w — the top-level window it actually lives in.  A menu item's nearest
 * shell is its XmMenuShell, NOT the application shell it popped up over; that distinction is exactly
 * what the wheel logic needs (a menu must not look like "the document window"). */
static Widget t81_shell(Widget w)
{
    if (!r5s.XtParent) return 0;
    for (; w; w = r5s.XtParent(w))
        if (t81_is_shell(w)) return w;
    return 0;
}

/* True if w lives inside a Motif menu (its nearest shell is an XmMenuShell) — the grab hooks key
 * the menu-depth counter on this so combo drop-lists (a different shell) keep scrolling. */
static int t81_in_menu(Widget w)
{
    Widget s = t81_shell(w);
    return s && strcmp(t81_class(s), "XmMenuShell") == 0;
}

/* Which scrollbar this wheel notch should drive, walking up from the widget under the pointer, in
 * priority order (retroXt.c rx_wheel_target verbatim in intent):
 *   1. a scrollbar directly under the pointer — HORIZONTAL or vertical — drive it;
 *   2. the vertical scrollbar of an enclosing XmScrolledWindow (open drop-list / scrolled content);
 *   3. the document scrollbar, but ONLY when the pointer is in the document's own shell (a menu /
 *      dialog popup has its OWN shell here, so it no longer scrolls the doc behind it). */
static Widget t81_wheel_target(XEvent *ev)
{
    Widget p, sw = 0;
    if (!r5s.XtWindowToWidget || !r5s.XtParent) return 0;
    for (p = r5s.XtWindowToWidget(ev->xbutton.display, ev->xbutton.window); p; p = r5s.XtParent(p)) {
        const char *c = t81_class(p);
        if (strcmp(c, "XmScrollBar") == 0)
            return p;                                   /* hovering a scrollbar — drive it */
        if (!sw && strcmp(c, "XmScrolledWindow") == 0 && r5s.XtGetValues) {
            Arg a[1];
            a[0].name = (String)"verticalScrollBar"; a[0].value = (XtArgVal)&sw;
            r5s.XtGetValues(p, a, 1);
        }
        if (t81_is_shell(p)) {                          /* reached this widget's own window */
            if (sw) return sw;
            if (p == t81_docshell)
                return t81_docsb ? t81_docsb : t81_tallsb;
            return 0;
        }
    }
    if (sw) return sw;
    return 0;
}

/* Motif ABI (no motif-dev headers here): the XmScrollBarCallbackStruct layout and the reason codes
 * are stable across OSF/Motif versions. */
typedef struct { int reason; XEvent *event; int value; int pixel; } T81SbCB;
#define T81_CR_VALUE_CHANGED 2
#define T81_CR_INCREMENT     3
#define T81_CR_DECREMENT     4
#define T81_CB_HAS_SOME      2            /* XtCallbackHasSome */

/* One wheel action: nudge the scrollbar and fire WP's own callback so the view actually scrolls.
 * (Motif's XtSetValues moves the thumb but does NOT invoke callbacks, so we invoke it ourselves —
 * exactly what a thumb-drag or arrow-release would do.)  Returns 1 if handled.
 * Some scrollbars (WP's font-name / point-size drop lists) scroll from the arrow increment/decrement
 * callback, not valueChanged — so if the step callback exists, emulate <t81_wheel_lines> arrow
 * clicks; otherwise fall back to value + valueChangedCallback (document / plain scrolled windows). */
static int t81_do_wheel(Widget sb, int dir /* -1 up, +1 down */, XEvent *ev)
{
    int val = 0, mn = 0, mx = 0, slider = 0, inc = 0, hi, nv;
    const char *stepcb = dir > 0 ? "incrementCallback" : "decrementCallback";
    int stepreason = dir > 0 ? T81_CR_INCREMENT : T81_CR_DECREMENT;
    T81SbCB cb;

    if (!sb) return 0;
    /* Every Xt call the drive needs must be resolved for this build. */
    if (!r5s.XtGetValues || !r5s.XtVaSetValues || !r5s.XtHasCallbacks || !r5s.XtCallCallbacks)
        return 0;

    {
        Arg a[5];
        a[0].name = (String)"value";      a[0].value = (XtArgVal)&val;
        a[1].name = (String)"minimum";    a[1].value = (XtArgVal)&mn;
        a[2].name = (String)"maximum";    a[2].value = (XtArgVal)&mx;
        a[3].name = (String)"sliderSize"; a[3].value = (XtArgVal)&slider;
        a[4].name = (String)"increment";  a[4].value = (XtArgVal)&inc;
        r5s.XtGetValues(sb, a, 5);
    }
    if (inc <= 0) inc = 1;
    hi = mx - slider;
    cb.event = ev;
    cb.pixel = 0;

    if (r5s.XtHasCallbacks(sb, (char *)stepcb) == T81_CB_HAS_SOME) {
        int i;
        for (i = 0; i < t81_wheel_lines; i++) {
            nv = val + dir * inc;
            if (nv > hi) nv = hi;
            if (nv < mn) nv = mn;
            if (nv == val) break;
            val = nv;
            r5s.XtVaSetValues(sb, "value", val, (char *)0);
            cb.reason = stepreason;
            cb.value  = val;
            r5s.XtCallCallbacks(sb, (char *)stepcb, (XtPointer)&cb);
        }
        t81_log("wheel(step) dir=%+d -> value %d", dir, val);
        return 1;
    }

    nv = val + dir * t81_wheel_lines * inc;
    if (nv > hi) nv = hi;
    if (nv < mn) nv = mn;
    if (nv == val) return 1;
    r5s.XtVaSetValues(sb, "value", nv, (char *)0);
    cb.reason = T81_CR_VALUE_CHANGED;
    cb.value  = nv;
    r5s.XtCallCallbacks(sb, "valueChangedCallback", (XtPointer)&cb);
    t81_log("wheel(vc) dir=%+d value %d -> %d", dir, val, nv);
    return 1;
}

/* ============================================================================================ *
 *  Detour hooks (installed over xwp's static prologues by takeoverWP81_full)
 * ============================================================================================ */

/* THE event funnel: every X event WP handles passes here.  Buttons 4/5 are the vertical wheel; WP
 * binds nothing to them.  We drive the right scrollbar on the press and swallow BOTH press and
 * release — the release must not reach WP, or an open combo drop-list treats the wheel click as
 * "dismiss".  While a Motif menu holds its modal grab, driving a scrollbar (repaint + X round-trips)
 * deadlocks the app, so we leave the wheel entirely to WP while a menu is up. */
Boolean t81_XtDispatchEvent(XEvent *ev)
{
    if (ev && (ev->type == ButtonPress || ev->type == ButtonRelease)) {
        unsigned int b = ev->xbutton.button;
        if ((b == 4 || b == 5) && t81_menu_depth == 0) {
            Widget target = t81_wheel_target(ev);
            if (target) {
                if (ev->type == ButtonPress)
                    t81_do_wheel(target, b == 5 ? +1 : -1, ev);
                return 1;                              /* swallow press AND release */
            }
            /* nothing to scroll -> let WP have the event */
        }
    }
    return r5s.real_dispatch ? r5s.real_dispatch(ev) : 0;
}

/* Track a posted Motif menu's modal grab so the wheel stands down while one is up.  Every spring-
 * loaded menu adds an Xt modal grab when posted and removes it when dismissed — a far more reliable
 * signal than XtPopup (Motif does not route menus through it).  Keyed on XmMenuShell so combo
 * drop-lists (a different shell) still scroll. */
void t81_XtAddGrab(Widget w, Boolean exclusive, Boolean spring_loaded)
{
    if (t81_in_menu(w)) {
        t81_menu_depth++;
        t81_log("menu grab+  depth=%d", t81_menu_depth);
    }
    if (r5s.real_addgrab) r5s.real_addgrab(w, exclusive, spring_loaded);
}

void t81_XtRemoveGrab(Widget w)
{
    if (t81_in_menu(w) && t81_menu_depth > 0) {
        t81_menu_depth--;
        t81_log("menu grab-  depth=%d", t81_menu_depth);
    }
    if (r5s.real_removegrab) r5s.real_removegrab(w);
}

/* Document-scrollbar discovery (retroXt.c rx_note_widget, trimmed to the wheel's needs): WP's own
 * "scrollbar0" is the document vertical scrollbar; keep the tallest vertical XmScrollBar as a
 * fallback in case that name ever changes. */
static void t81_note_widget(Widget w)
{
    const char *cls = t81_class(w);
    if (strcmp(cls, "XmScrollBar") != 0) return;
    {
        const char *name = r5s.XtName ? r5s.XtName(w) : 0;
        if (name && strcmp(name, "scrollbar0") == 0) {
            t81_docsb    = w;
            t81_docshell = t81_shell(w);
            t81_log("captured document vscroll 'scrollbar0'");
        } else if (r5s.XtGetValues) {
            Dimension h = 0, wd = 0;
            Arg a[2];
            a[0].name = (String)"height"; a[0].value = (XtArgVal)&h;
            a[1].name = (String)"width";  a[1].value = (XtArgVal)&wd;
            r5s.XtGetValues(w, a, 2);
            if (h > wd && h > t81_tallh) { t81_tallsb = w; t81_tallh = h; }
        }
    }
}

void t81_XtManageChild(Widget w)
{
    t81_note_widget(w);
    if (r5s.real_managechild) r5s.real_managechild(w);
}

void t81_XtManageChildren(WidgetList children, Cardinal num)
{
    Cardinal i;
    for (i = 0; i < num; i++) t81_note_widget(children[i]);
    if (r5s.real_managechildren) r5s.real_managechildren(children, num);
}

/* 8.0 main-loop replacement.  WP's primary loop is XtAppMainLoop, whose XtDispatchEvent call is
 * libXt-internal and so is NOT reached by a GOT interpose over WP's own XtDispatchEvent import —
 * which is why the doc window (driven by XtAppMainLoop) would never see the wheel while modal
 * dialogs (WP's own NextEvent+DispatchEvent loops) would.  We GOT-interpose XtAppMainLoop with this
 * faithful re-implementation (the canonical X11R6 body) so the main loop dispatches through OUR
 * handler.  WP imports no XtApp{Set,Get}ExitFlag, so the plain infinite loop is exactly equivalent.
 * 8.1 does not use this: its static detour patches the XtDispatchEvent function itself. */
void t81_XtAppMainLoop(XtAppContext app)
{
    XEvent ev;
    if (!r5s.XtAppNextEvent) return;                 /* misconfigured — do not spin */
    for (;;) {
        r5s.XtAppNextEvent(app, &ev);
        t81_XtDispatchEvent(&ev);
    }
}

/* ============================================================================================ *
 *  Public install entry — called from applyWp8_1_Fixes at integration (NOT wired yet)
 * ============================================================================================ */
/* One-time env: lines per wheel notch (RETROXT_WHEEL_LINES kept for parity; RETRO5_ prefix too).
 * Non-static + called by BOTH installs (8.0 patch5.c and 8.1 takeoverWP81_full) so the setting
 * applies whichever way the shared handlers were installed. */
void t81_wheel_config(void)
{
    const char *wl = getenv("RETRO5_WHEEL_LINES");
    if (!wl || !*wl) wl = getenv("RETROXT_WHEEL_LINES");
    if (wl && *wl) { int n = atoi(wl); if (n > 0 && n < 100) t81_wheel_lines = n; }
}

void takeoverWP81_full(void)
{
    t81_wheel_config();

    /* ---- per-build fill: the 8.1 static-detour targets (all CONFIRMED in wp81_detours.h) ---- */
    r5s.xt_dispatch_va       = 0x08657ab0;   /* XtDispatchEvent, steal 6 */
    r5s.xt_addgrab_va        = 0x08657d00;   /* XtAddGrab,       steal 6 */
    r5s.xt_removegrab_va     = 0x08657da0;   /* XtRemoveGrab,    steal 5 */
    r5s.xt_managechild_va    = 0x0865e040;   /* XtManageChild,   steal 5 */
    r5s.xt_managechildren_va = 0x0865df30;   /* XtManageChildren,steal 6 */

    /* ---- per-build fill: the Xt callbacks the shared wheel logic makes ----
     * Sourced from installer/wp81port/wp81_fullsyms.s (the authoritative byte-exact symbolization of
     * xwp's static X11+Xt region; BASE 0x0864d9d0 + the symbol's .org).  Provenance is cross-checked:
     * XtManageChild / XtManageChildren computed the same way land EXACTLY on the wp81_detours.h
     * addresses, so this table is trustworthy.  These are absolute VAs into xwp's .text — valid ONLY
     * for the fingerprinted 8.1 build (matchBinaryHash has already gated us here). */
    r5s.XtWindowToWidget = (Widget (*)(Display *, Window))            0x08656ce0;
    r5s.XtParent         = (Widget (*)(Widget))                      0x0865c220;
    r5s.XtName           = (char  *(*)(Widget))                      0x0865c230;
    r5s.XtWindow         = (Window (*)(Widget))                      0x0865c110;
    r5s.XtHasCallbacks   = (int    (*)(Widget, char *))              0x0864e880;
    r5s.XtCallCallbacks  = (void   (*)(Widget, char *, XtPointer))   0x0864e7a0;
    r5s.XtVaSetValues    = (void   (*)(Widget, ...))                 0x086742f0;
    /* The wheel READS scrollbar values through the non-varargs XtGetValues (the varargs XtVaGetValues
     * form is not symbolized in xwp's static build).  0x08659f70 is xwp's static XtGetValues. */
    r5s.XtGetValues      = (void   (*)(Widget, ArgList, Cardinal))   0x08659f70;

    /* ---- install the detours over xwp's static prologues (shared trampoline + entry writer) ----
     * The trampoline (original prologue + jmp back) is captured straight into r5s.real_*, which is
     * exactly what the shared handlers chain to. */
    {
        int ok = 0;
        ok += t81_detour(r5s.xt_dispatch_va,       6, (void *)t81_XtDispatchEvent,  (void **)&r5s.real_dispatch);
        ok += t81_detour(r5s.xt_addgrab_va,        6, (void *)t81_XtAddGrab,        (void **)&r5s.real_addgrab);
        ok += t81_detour(r5s.xt_removegrab_va,     5, (void *)t81_XtRemoveGrab,     (void **)&r5s.real_removegrab);
        ok += t81_detour(r5s.xt_managechild_va,    5, (void *)t81_XtManageChild,    (void **)&r5s.real_managechild);
        ok += t81_detour(r5s.xt_managechildren_va, 6, (void *)t81_XtManageChildren, (void **)&r5s.real_managechildren);
        t81_log("takeoverWP81_full: %d/5 detours installed (wheel_lines=%d, XtGetValues=%s)",
                ok, t81_wheel_lines, r5s.XtGetValues ? "set" : "TODO");
    }
}
