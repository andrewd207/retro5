/*
 * retroXt.so - a thin Xt Intrinsics interposer for WordPerfect 8 (libc5) on
 * modern Linux, sitting in front of the system libXt.so.6.
 *
 * WHY THIS WORKS
 *   WP's scrollbars / buttons / radio buttons are Motif (libXm) widgets, and in
 *   the 8.0 build Motif is STATICALLY linked - there is no dynamic Xm symbol to
 *   hook.  But Motif is only a widget layer on top of Xt, and Xt IS dynamic
 *   (xwp imports 148 Xt* symbols from libXt.so.6).  Every event in the whole
 *   app funnels through XtDispatchEvent, and every managed widget/gadget passes
 *   through XtManageChild(ren).  So by shadowing a handful of Xt entry points we
 *   can observe - and later reroute - the entire Motif UI without ever touching
 *   a Motif symbol.
 *
 * TWO LOAD MODES (this same .so serves both)
 *   trace/dev : LD_PRELOAD=.../retroXt.so xwp        (no binary patch)
 *   permanent : rewrite xwp's DT_NEEDED "libXt.so.6"(10) -> "retroXt.so"(10) and
 *               drop this .so in shbin10; its own NEEDED pulls the real libXt in,
 *               so unhooked symbols fall through by name (earlier object wins).
 *   In both modes the real implementations are reached via dlsym(RTLD_NEXT,...).
 *
 * THIS BUILD IS TRACE-ONLY: it observes and forwards everything, changing no
 * behaviour.  One run tells us the real scrollbar widget names and confirms the
 * wheel (Button4/5) events reach the dispatch funnel.  Then we flip on the drive.
 */

#include <X11/Intrinsic.h>
#include <X11/IntrinsicP.h>
#include <X11/CoreP.h>
#include <X11/Xlib.h>
#include <cairo/cairo.h>
#include <cairo/cairo-xlib.h>
#include <math.h>

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#ifdef RX_STATIC81
/* WP 8.1 build: xwp links Xt/X11 STATICALLY, so the hooks below can't be reached
 * by LD_PRELOAD symbol interposition -- they are installed as inline detours over
 * the fixed absolute addresses mapped in wp81port/wp81_xt_symbols.map, and the
 * originals are reached through the detour trampolines (orig_<name>). */
#include "wp81port/detour81.h"
#include "wp81port/wp81_detours.h"
#include "wp81port/wp81_fingerprint.h"
/* fail-safe: verify the loaded exe IS the mapped build before patching hardcoded
 * addresses (else a different/updated xwp gets corrupted).  See wp81_fpguard.c. */
extern int wp81_fingerprint_ok(unsigned char got16[16]);
#endif

/* ---------------------------------------------------------- Cairo isolation --
 * WP is a libc5 program; retro5.so exports libc5 shims (strlen/malloc/free/...)
 * that shadow glibc across the whole process via the flat symbol namespace.  If
 * Cairo is a plain NEEDED, its (and fontconfig's) libc calls bind to those libc5
 * shims -> heap mismatch -> hang in font init (proven by gdb: cairo_text_extents
 * -> FcInit -> retro5 strlen).  So we dlopen Cairo with RTLD_DEEPBIND, which makes
 * it resolve libc from its OWN deps (glibc) first, and call it via pointers. */
static cairo_surface_t *(*p_cairo_xlib_surface_create)(Display *, Drawable, Visual *, int, int);
static cairo_t *(*p_cairo_create)(cairo_surface_t *);
static void (*p_cairo_destroy)(cairo_t *);
static void (*p_cairo_surface_destroy)(cairo_surface_t *);
static void (*p_cairo_surface_flush)(cairo_surface_t *);
static void (*p_cairo_paint)(cairo_t *);
static void (*p_cairo_set_source_rgb)(cairo_t *, double, double, double);
static void (*p_cairo_fill)(cairo_t *);
static void (*p_cairo_fill_preserve)(cairo_t *);
static void (*p_cairo_stroke)(cairo_t *);
static void (*p_cairo_move_to)(cairo_t *, double, double);
static void (*p_cairo_line_to)(cairo_t *, double, double);
static void (*p_cairo_arc)(cairo_t *, double, double, double, double, double);
static void (*p_cairo_new_sub_path)(cairo_t *);
static void (*p_cairo_close_path)(cairo_t *);
static void (*p_cairo_set_line_width)(cairo_t *, double);
static void (*p_cairo_set_line_cap)(cairo_t *, cairo_line_cap_t);
static void (*p_cairo_set_line_join)(cairo_t *, cairo_line_join_t);
static void (*p_cairo_set_dash)(cairo_t *, const double *, int, double);
static void (*p_cairo_select_font_face)(cairo_t *, const char *, cairo_font_slant_t, cairo_font_weight_t);
static void (*p_cairo_set_font_size)(cairo_t *, double);
static void (*p_cairo_text_extents)(cairo_t *, const char *, cairo_text_extents_t *);
static void (*p_cairo_show_text)(cairo_t *, const char *);
static int  (*p_cairo_status)(cairo_t *);
static const char *(*p_cairo_status_to_string)(int);
static cairo_surface_t *(*p_cairo_image_surface_create)(int, int, int);
static unsigned char *(*p_cairo_image_surface_get_data)(cairo_surface_t *);
static int  (*p_cairo_image_surface_get_stride)(cairo_surface_t *);
static void (*p_cairo_set_source_surface)(cairo_t *, cairo_surface_t *, double, double);
static int  rx_cairo_ok;

static void rx_load_cairo(void)
{
    void *h = dlopen("libcairo.so.2", RTLD_NOW | RTLD_DEEPBIND);
    if (!h) return;
#define LDC(sym) (*(void **)&p_##sym = dlsym(h, #sym))
    LDC(cairo_xlib_surface_create); LDC(cairo_create); LDC(cairo_destroy);
    LDC(cairo_surface_destroy); LDC(cairo_surface_flush); LDC(cairo_paint);
    LDC(cairo_set_source_rgb); LDC(cairo_fill); LDC(cairo_fill_preserve);
    LDC(cairo_stroke); LDC(cairo_move_to); LDC(cairo_line_to); LDC(cairo_arc);
    LDC(cairo_new_sub_path); LDC(cairo_close_path); LDC(cairo_set_line_width);
    LDC(cairo_set_line_cap); LDC(cairo_set_line_join); LDC(cairo_set_dash); LDC(cairo_select_font_face);
    LDC(cairo_set_font_size); LDC(cairo_text_extents); LDC(cairo_show_text);
    LDC(cairo_status); LDC(cairo_status_to_string);
    LDC(cairo_image_surface_create); LDC(cairo_image_surface_get_data);
    LDC(cairo_image_surface_get_stride); LDC(cairo_set_source_surface);
#undef LDC
    rx_cairo_ok = (p_cairo_create && p_cairo_xlib_surface_create &&
                   p_cairo_show_text && p_cairo_text_extents) ? 1 : 0;
}

#define cairo_xlib_surface_create p_cairo_xlib_surface_create
#define cairo_create              p_cairo_create
#define cairo_destroy             p_cairo_destroy
#define cairo_surface_destroy     p_cairo_surface_destroy
#define cairo_surface_flush       p_cairo_surface_flush
#define cairo_paint               p_cairo_paint
#define cairo_set_source_rgb      p_cairo_set_source_rgb
#define cairo_fill                p_cairo_fill
#define cairo_fill_preserve       p_cairo_fill_preserve
#define cairo_stroke              p_cairo_stroke
#define cairo_move_to             p_cairo_move_to
#define cairo_line_to             p_cairo_line_to
#define cairo_arc                 p_cairo_arc
#define cairo_new_sub_path        p_cairo_new_sub_path
#define cairo_close_path          p_cairo_close_path
#define cairo_set_line_width      p_cairo_set_line_width
#define cairo_set_line_cap        p_cairo_set_line_cap
#define cairo_set_line_join       p_cairo_set_line_join
#define cairo_set_dash            p_cairo_set_dash
#define cairo_select_font_face    p_cairo_select_font_face
#define cairo_set_font_size       p_cairo_set_font_size
#define cairo_text_extents        p_cairo_text_extents
#define cairo_show_text           p_cairo_show_text
#define cairo_status              p_cairo_status
#define cairo_status_to_string    p_cairo_status_to_string
#define cairo_image_surface_create     p_cairo_image_surface_create
#define cairo_image_surface_get_data   p_cairo_image_surface_get_data
#define cairo_image_surface_get_stride p_cairo_image_surface_get_stride
#define cairo_set_source_surface       p_cairo_set_source_surface

/* ------------------------------------------------------------------ logging
 *
 * CRITICAL: WP is a libc5 program whose libc symbols are supplied by retro5.so,
 * which exports its own vfprintf/fopen/fputs/... using the *libc5* FILE layout.
 * Symbol resolution is a flat global namespace, so a stdio call from this shim
 * can bind to retro5's libc5 version instead of glibc's - handing a glibc FILE*
 * to a libc5 vfprintf, which silently prints nothing (that was the "[retroXt] "
 * prefix with an empty body in the first trace).  So we never touch FILE*:
 * format into a local buffer and emit with the raw write(2) syscall, and pull
 * vsnprintf straight from glibc by handle so formatting can't be hijacked.
 * (retro5 wraps write/open too, but they're thin syscall stubs with identical
 * ABI - we bypass even those via syscall(2), which retro5 does not export.)
 */

static int rx_fd = 2;                                   /* default: stderr      */
static int (*rx_vsnprintf)(char *, size_t, const char *, va_list);
static int rx_verbose;                                  /* RETROXT_TRACE: dump every widget */
static int rx_wheel_lines = 3;                          /* text lines per wheel notch       */
static int rx_skin = 1;                                 /* RETROXT_SKIN: reskin Motif look  */
static int rx_shadow = 2;                               /* RETROXT_SHADOW: raised bevel px  */
static int rx_draw = 1;                                 /* RETROXT_DRAW: custom-draw scrollbars */
static int rx_drawbtn = 1;                              /* RETROXT_BTN: custom-draw buttons  */
static int rx_logdraw;                                  /* RETROXT_LOGDRAW: log every draw op */
static int rx_debugfill;                                /* RETROXT_DEBUGFILL: paint buttons solid red */
static Window rx_list_win;                              /* XmList window under observation (RETROXT_TRACE) */
static Widget rx_list_widget;

/* GC -> current clip rectangle cache.  Motif sets a GC's clip to a gadget's exact
 * bounds before drawing it; XGetGCValues can't read clip rects, so we snoop
 * XSetClipRectangles/XSetClipMask and use the clip as the gadget's true rect. */
#define RX_CLIPMAX 128
static struct { GC gc; int x, y, w, h; } rx_clips[RX_CLIPMAX];
static int rx_nclip;
static void rx_clip_store(GC gc, int x, int y, int w, int h)
{
    int i;
    for (i = 0; i < rx_nclip; i++) if (rx_clips[i].gc == gc) { rx_clips[i].x = x; rx_clips[i].y = y; rx_clips[i].w = w; rx_clips[i].h = h; return; }
    if (rx_nclip < RX_CLIPMAX) { rx_clips[rx_nclip].gc = gc; rx_clips[rx_nclip].x = x; rx_clips[rx_nclip].y = y; rx_clips[rx_nclip].w = w; rx_clips[rx_nclip].h = h; rx_nclip++; }
}
static void rx_clip_none(GC gc) { int i; for (i = 0; i < rx_nclip; i++) if (rx_clips[i].gc == gc) { rx_clips[i].w = 0; return; } }
static int rx_clip_get(GC gc, int *x, int *y, int *w, int *h)
{
    int i;
    for (i = 0; i < rx_nclip; i++) if (rx_clips[i].gc == gc && rx_clips[i].w > 0) { *x = rx_clips[i].x; *y = rx_clips[i].y; *w = rx_clips[i].w; *h = rx_clips[i].h; return 1; }
    return 0;
}

static void rx_raw(const char *p, size_t n)
{
    while (n) {
        long w = syscall(SYS_write, rx_fd, p, n);
        if (w <= 0) break;
        p += w;
        n -= (size_t)w;
    }
}

static void rx_log(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;

    memcpy(buf, "[retroXt] ", 10);
    va_start(ap, fmt);
    n = rx_vsnprintf ? rx_vsnprintf(buf + 10, sizeof buf - 12, fmt, ap)
                     : vsnprintf   (buf + 10, sizeof buf - 12, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof buf - 12) n = sizeof buf - 12;
    buf[10 + n] = '\n';
    rx_raw(buf, (size_t)n + 11);                        /* 10 prefix + n + '\n'  */
}

#ifdef RX_STATIC81
/* Trampoline pointers to the ORIGINAL Xt/X11 bodies inside xwp -- set by
 * detour_install().  One per interposed function (exact signature via typeof).
 * The 5 batch/i18n variants that xwp never links (XDrawArcs/XDrawRectangles/
 * XFillArcs/XmbDraw*) get a NULL trampoline: their hooks compile but are never
 * installed nor called. */
#define X(n, a, s) typeof(&n) orig_##n;
WP81_DETOUR_LIST(X)
#undef X
typeof(&XDrawArcs)          orig_XDrawArcs;
typeof(&XDrawRectangles)    orig_XDrawRectangles;
typeof(&XFillArcs)          orig_XFillArcs;
typeof(&XmbDrawString)      orig_XmbDrawString;
typeof(&XmbDrawImageString) orig_XmbDrawImageString;

static void rx_detour_log(const char *fmt, ...)
{
    char b[256]; va_list ap; int n;
    va_start(ap, fmt);
    n = rx_vsnprintf ? rx_vsnprintf(b, sizeof b, fmt, ap) : 0;
    va_end(ap);
    if (n > 0) syscall(SYS_write, rx_fd > 0 ? rx_fd : 2, b, (size_t)n);
}

/* Patch every mapped prologue to jump to our hook (same-named function below). */
static void rx_install_detours81(void)
{
    static detour_t tab[WP81_NDETOUR];
    int n = 0;
#define X(nm, ad, st)                                            \
    tab[n].name   = #nm;                                         \
    tab[n].target = (void *)(ad);                               \
    tab[n].hook   = (void *)nm;              /* our hook */       \
    tab[n].orig   = (void **)&orig_##nm;     /* -> trampoline */  \
    tab[n].steal  = (st);                                        \
    n++;
    WP81_DETOUR_LIST(X)
#undef X
    detour_log = rx_detour_log;
    detour_install(tab, n);
}
#endif /* RX_STATIC81 */

__attribute__((constructor))
static void rx_init(void)
{
    void *libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    char *(*g_getenv)(const char *) = libc ? (char *(*)(const char *))dlsym(libc, "getenv") : 0;
    const char *path;

    const char *wl;

    if (libc) rx_vsnprintf = (int (*)(char *, size_t, const char *, va_list))dlsym(libc, "vsnprintf");
    path = g_getenv ? g_getenv("RETROXT_LOG") : getenv("RETROXT_LOG");
    if (path && *path) {
        int fd = syscall(SYS_open, path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) rx_fd = fd;
    }
    rx_verbose = (g_getenv ? g_getenv("RETROXT_TRACE") : getenv("RETROXT_TRACE")) ? 1 : 0;
    {
        const char *s = g_getenv ? g_getenv("RETROXT_SKIN") : getenv("RETROXT_SKIN");
        const char *sh = g_getenv ? g_getenv("RETROXT_SHADOW") : getenv("RETROXT_SHADOW");
        const char *dr = g_getenv ? g_getenv("RETROXT_DRAW") : getenv("RETROXT_DRAW");
        if (s && (s[0] == '0' || s[0] == 'n' || s[0] == 'N')) rx_skin = 0;
        if (sh && *sh) { int n = atoi(sh); if (n >= 0 && n <= 5) rx_shadow = n; }
        if (dr && (dr[0] == '0' || dr[0] == 'n' || dr[0] == 'N')) rx_draw = 0;
        {
            const char *bt = g_getenv ? g_getenv("RETROXT_BTN") : getenv("RETROXT_BTN");
            const char *lg = g_getenv ? g_getenv("RETROXT_LOGDRAW") : getenv("RETROXT_LOGDRAW");
            if (bt && (bt[0] == '0' || bt[0] == 'n' || bt[0] == 'N')) rx_drawbtn = 0;
            if (lg && lg[0] && lg[0] != '0' && lg[0] != 'n' && lg[0] != 'N') rx_logdraw = 1;
            {
                const char *df = g_getenv ? g_getenv("RETROXT_DEBUGFILL") : getenv("RETROXT_DEBUGFILL");
                if (df && df[0] && df[0] != '0' && df[0] != 'n' && df[0] != 'N') rx_debugfill = 1;
            }
        }
    }
    wl = g_getenv ? g_getenv("RETROXT_WHEEL_LINES") : getenv("RETROXT_WHEEL_LINES");
    if (wl && *wl) { int n = atoi(wl); if (n > 0 && n < 100) rx_wheel_lines = n; }
    rx_load_cairo();
    if (!rx_cairo_ok) { rx_draw = 0; rx_drawbtn = 0; }   /* no cairo -> Motif draws */
#ifdef RX_STATIC81
    {   /* SAFEGUARD: the detours + shim use hardcoded absolute addresses valid ONLY for
         * the exact build they were mapped from.  MD5 the running exe first; on any
         * mismatch install NOTHING so a different/updated xwp runs 100% stock. */
        unsigned char got[16]; int i; char h[33];
        static const char hx[] = "0123456789abcdef";
        if (wp81_fingerprint_ok(got)) {
            rx_install_detours81();   /* patch xwp's static Xt/X11 prologues -> our hooks */
        } else {
            for (i = 0; i < 16; i++) { h[i*2] = hx[got[i] >> 4]; h[i*2+1] = hx[got[i] & 15]; }
            h[32] = 0;
            rx_draw = 0; rx_drawbtn = 0;   /* belt-and-braces: nothing to draw either */
            rx_log("FINGERPRINT: this exe md5=%s is not a whitelisted WP 8.1 build", h);
            rx_log("  -> reskin DISABLED, WP runs unmodified.");
        }
    }
#endif
    rx_log("loaded (wheel-scroll %d/notch; cairo=%s; RETROXT_TRACE=1 dumps widgets)",
           rx_wheel_lines, rx_cairo_ok ? "on" : "OFF");
}

/* ------------------------------------------------ real-symbol resolution ---- */

#ifdef RX_STATIC81
/* 8.1: the original lives at a fixed address in xwp, reached via the detour
 * trampoline set up in the constructor.  No dlsym -- there is no dynamic symbol. */
#define REAL(name) typeof(&name) real_##name = orig_##name; (void)real_##name;
#else
#define REAL(name) \
    static typeof(&name) real_##name; \
    if (!real_##name) real_##name = (typeof(&name))dlsym(RTLD_NEXT, #name);
#endif

/* class name of a widget OR gadget; RectObj/Object class records share the
 * class_name slot layout with Core, so this is safe for gadgets too. */
static const char *rx_class(Widget w)
{
    WidgetClass c;
    if (!w) return "(null)";
    c = XtClass(w);
    return (c && c->core_class.class_name) ? c->core_class.class_name : "(?)";
}

/* True if w is a shell - its class name ends in "Shell" (XmMenuShell,
 * XmDialogShell, ApplicationShell, TransientShell, ...). */
static int rx_is_shell(Widget w)
{
    const char *c = rx_class(w);
    size_t n = strlen(c);
    return n >= 5 && strcmp(c + n - 5, "Shell") == 0;
}

/* Nearest enclosing shell of w - the top-level window it actually lives in. A
 * menu item's nearest shell is its XmMenuShell, NOT the application shell it is a
 * popup CHILD of; that distinction is exactly what the wheel logic needs (a menu
 * must not look like "the document window"). */
static Widget rx_shell(Widget w)
{
    for (; w; w = XtParent(w))
        if (rx_is_shell(w)) return w;
    return 0;
}

/* True if w lives inside a Motif menu (its nearest shell is an XmMenuShell). */
static int rx_in_menu(Widget w)
{
    Widget s = rx_shell(w);
    return s && strcmp(rx_class(s), "XmMenuShell") == 0;
}

/* ---- window-size cache: never do our own blocking XGetGeometry in the render
 * path (that deadlocks inside a modal dialog's grab).  We record sizes from
 * Motif's OWN XGetGeometry calls and from ConfigureNotify, drop them on
 * XDestroyWindow, and fall back to the (client-side) widget resources. */
#define RX_GEOM_N 1024
static struct { Window win; unsigned short w, h; } rx_geom[RX_GEOM_N];

static void rx_geom_set(Window win, unsigned int w, unsigned int h)
{
    int i;
    if (!win || w < 1 || h < 1) return;
    i = (int)(win % RX_GEOM_N);
    rx_geom[i].win = win; rx_geom[i].w = (unsigned short)w; rx_geom[i].h = (unsigned short)h;
}
static int rx_geom_get(Window win, unsigned int *w, unsigned int *h)
{
    int i = (int)(win % RX_GEOM_N);
    if (rx_geom[i].win == win) { *w = rx_geom[i].w; *h = rx_geom[i].h; return 1; }
    return 0;
}
static void rx_geom_del(Window win)
{
    int i = (int)(win % RX_GEOM_N);
    if (rx_geom[i].win == win) rx_geom[i].win = 0;
}
/* Real window size: cache first (no round-trip in the hot path); on a miss fall
 * back to a real XGetGeometry (which our interposer also caches) - NOT the
 * widget width/height resources, which are over-allocated (drew buttons huge). */
static int rx_win_size(Widget w, Window win, unsigned int *W, unsigned int *H)
{
    Window root; int x, y; unsigned int bw, dep;
    Display *d;
    if (rx_geom_get(win, W, H) && *W >= 2 && *H >= 2) return 1;
    d = XtDisplayOfObject(w);
    if (d && XGetGeometry(d, win, &root, &x, &y, W, H, &bw, &dep) && *W >= 2 && *H >= 2)
        return 1;
    return 0;
}

/* ------------------------------------------------------ appearance reskin ----
 * Modernize the Motif look WITHOUT touching Motif's draw code: rewrite the
 * appearance resources (shadow thickness + colors) at widget-manage time.  The
 * chunky 3D bevel and battleship gray are the dated signature; we flatten the
 * bevel to a thin outline and apply a clean light palette with a blue accent for
 * armed/selected state.  RETROXT_SKIN=0 disables (to A/B against stock Motif). */

static int   rx_pal_ready;
static Pixel rx_cBg, rx_cTop, rx_cBot, rx_cFg, rx_cTrough, rx_cAccent, rx_cArm;

static Pixel rx_alloc(Display *d, Colormap cm, int r, int g, int b)
{
    XColor c;
    c.red = r << 8; c.green = g << 8; c.blue = b << 8;
    c.flags = DoRed | DoGreen | DoBlue;
    if (XAllocColor(d, cm, &c)) return c.pixel;
    return BlackPixel(d, DefaultScreen(d));
}

static void rx_init_palette(Widget w)
{
    Display *d = XtDisplayOfObject(w);
    Colormap cm;
    if (!d) return;
    cm = DefaultColormap(d, DefaultScreen(d));
    rx_cBg     = rx_alloc(d, cm, 232, 232, 232);   /* widget face   #E8E8E8 */
    rx_cTop    = rx_alloc(d, cm, 255, 255, 255);   /* bright top edge  #FFFFFF */
    rx_cBot    = rx_alloc(d, cm, 140, 140, 140);   /* firm dark edge   #8C8C8C */
    rx_cFg     = rx_alloc(d, cm,  26,  26,  26);   /* text          #1A1A1A */
    rx_cTrough = rx_alloc(d, cm, 192, 192, 192);   /* scrollbar trough #C0C0C0 */
    rx_cAccent = rx_alloc(d, cm,  58, 123, 213);   /* selected indicator #3A7BD5 */
    rx_cArm    = rx_alloc(d, cm, 205, 223, 247);   /* soft hover highlight #CDDFF7 */
    rx_pal_ready = 1;
}

static int rx_in_list(const char *cls, const char *const *list)
{
    for (; *list; list++)
        if (!strcmp(cls, *list)) return 1;
    return 0;
}

/* Every chrome class we recolor.  Content areas (XmText, XmList, XmDrawingArea,
 * XmDisplay) are deliberately absent - WP draws its own content there. */
static const char *const RX_CHROME[] = {
    "XmScrollBar", "XmPushButton", "XmPushButtonGadget", "XmDrawnButton",
    "XmCascadeButton", "XmCascadeButtonGadget", "XmArrowButton",
    "XmToggleButton", "XmToggleButtonGadget", "XmFrame", "XmRowColumn",
    "XmForm", "XmBulletinBoard", "XmSeparator", "XmSeparatorGadget",
    "XmLabel", "XmLabelGadget", "XmPanedWindow", "XmSash", "XmScrolledWindow",
    "XiCombinationBox", 0
};
static const char *const RX_TEXT[] = {   /* also get a dark foreground */
    "XmPushButton", "XmPushButtonGadget", "XmDrawnButton", "XmCascadeButton",
    "XmCascadeButtonGadget", "XmToggleButton", "XmToggleButtonGadget",
    "XmLabel", "XmLabelGadget", 0
};
static const char *const RX_ARM[] = {    /* armed/hover highlight */
    "XmPushButton", "XmPushButtonGadget", "XmDrawnButton", "XmArrowButton",
    "XmCascadeButton", "XmCascadeButtonGadget", 0
};
/* Classes that keep a visible RAISED bevel so they read as interactive - the
 * rest (containers, labels, toolbars, menu items) stay flat. */
static const char *const RX_RAISED[] = {
    "XmPushButton", "XmPushButtonGadget", "XmScrollBar", "XmArrowButton",
    "XmToggleButton", "XmToggleButtonGadget", "XmFrame", "XiCombinationBox", 0
};

static void rx_restyle(Widget w, const char *cls)
{
    int thick;
    if (!rx_skin) return;
    if (!rx_pal_ready) rx_init_palette(w);
    if (!rx_pal_ready) return;
    if (!strcmp(cls, "XmText") || !strcmp(cls, "XmTextField")) {   /* flat, thin-bordered field */
        XtVaSetValues(w, "shadowThickness", 1,
                         "topShadowColor", rx_cBot, "bottomShadowColor", rx_cBot, (char *)0);
        return;                                  /* keep its (white) background */
    }
    if (!rx_in_list(cls, RX_CHROME)) return;

    thick = rx_in_list(cls, RX_RAISED) ? rx_shadow : 1;
    if (rx_in_menu(w)) thick = 0;                /* menu items: flat, label-like */
    XtVaSetValues(w, "shadowThickness", thick,
                     "background", rx_cBg,
                     "topShadowColor", rx_cTop,
                     "bottomShadowColor", rx_cBot, (char *)0);
    /* Roomier dropdown menu items (wider + a bit taller) for a modern feel. */
    if (rx_in_menu(w) &&
        (!strcmp(cls, "XmPushButton") || !strcmp(cls, "XmCascadeButton") ||
         !strcmp(cls, "XmToggleButton") || !strcmp(cls, "XmLabel")))
        XtVaSetValues(w, "marginWidth", 16, "marginHeight", 3, (char *)0);
    if (rx_in_list(cls, RX_TEXT))
        XtVaSetValues(w, "foreground", rx_cFg, (char *)0);
    if (rx_in_list(cls, RX_ARM))                 /* soft hover highlight (hot-track) */
        XtVaSetValues(w, "armColor", rx_cArm, (char *)0);
    if (!strcmp(cls, "XmScrollBar"))
        XtVaSetValues(w, "troughColor", rx_cTrough, (char *)0);
    if (!strcmp(cls, "XmToggleButton") || !strcmp(cls, "XmToggleButtonGadget"))
        XtVaSetValues(w, "selectColor", rx_cAccent, (char *)0);
}

/* Composite classes worth descending into to reskin their children/gadgets. */
static const char *const RX_CONTAINER[] = {
    "XmRowColumn", "XmForm", "XmFrame", "XmScrolledWindow", "XmPanedWindow",
    "XmBulletinBoard", "XmMainWindow", "XiCombinationBox", 0
};
static int rx_is_container(Widget w)
{
    return rx_is_shell(w) || rx_in_list(rx_class(w), RX_CONTAINER);
}

/* Recolor w and (for composites) its whole child tree - used to reskin a menu
 * the instant it posts, since its item gadgets are colored by WP during the post
 * and would otherwise draw gray until individually armed. */
static void rx_restyle_tree(Widget w)
{
    if (!w) return;
    rx_restyle(w, rx_class(w));
    if (rx_is_container(w)) {
        WidgetList kids = 0;
        Cardinal n = 0, i;
        XtVaGetValues(w, "children", &kids, "numChildren", &n, (char *)0);
        for (i = 0; i < n && kids; i++)
            rx_restyle_tree(kids[i]);
    }
}

/* ---------------------------------------------- custom drawing (Cairo, AA) ----
 * A Motif scrollbar is a real X window, so we paint it ourselves with Cairo -
 * anti-aliased, rounded, no ancient arrows - while leaving the Motif widget in
 * place to handle drag/page events and its wiring to WP.  We suppress Motif's
 * own Expose paint and redraw on every value-change callback to stay in sync. */

static Widget rx_sbwidgets[64];         /* scrollbars we custom-draw            */
static int    rx_nsb;
static int    rx_in_my_draw;            /* guard: let our own Cairo requests pass */

/* Is this drawable one of our scrollbar windows? (used to drop Motif's paints) */
static int rx_is_sb_drawable(Drawable dr)
{
    int i;
    if (rx_in_my_draw) return 0;
    for (i = 0; i < rx_nsb; i++)
        if (rx_sbwidgets[i] && XtIsRealized(rx_sbwidgets[i]) &&
            XtWindow(rx_sbwidgets[i]) == (Window)dr)
            return 1;
    return 0;
}

static void rx_rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r > w / 2) r = w / 2;
    if (r > h / 2) r = h / 2;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,          M_PI / 2);
    cairo_arc(cr, x + r,     y + h - r, r, M_PI / 2,   M_PI);
    cairo_arc(cr, x + r,     y + r,     r, M_PI,       3 * M_PI / 2);
    cairo_close_path(cr);
}

static void rx_draw_scrollbar(Widget w)
{
    Display *d = XtDisplayOfObject(w);
    Window win;
    Dimension W = 0, H = 0;
    int val = 0, mn = 0, mx = 0, ss = 0, vert, range;
    double pad = 3.0, slen, spos, r, breadth, arrow, start, full, thick;
    Boolean sa = True;                              /* this scrollbar's own arrows */
    cairo_surface_t *sf;
    cairo_t *cr;

    if (!rx_draw || !d) return;
    win = XtWindow(w);
    if (!win) return;
    XtVaGetValues(w, "value", &val, "minimum", &mn, "maximum", &mx,
                     "sliderSize", &ss, "showArrows", &sa, (char *)0);
    {   /* real window size WITHOUT a blocking round-trip (cache / resources) */
        unsigned int gw = 0, gh = 0;
        if (!rx_win_size(w, win, &gw, &gh)) return;
        W = (Dimension)gw; H = (Dimension)gh;
    }
    XSetWindowBackgroundPixmap(d, win, None);            /* no server auto-clear */
    if (W < 2 || H < 2) return;

    rx_in_my_draw = 1;
#ifdef RX_STATIC81
    /* 8.1: xwp's STATIC libX11 owns the Display.  A cairo xlib surface would drive that
     * Display through the MODERN libX11 cairo links (two instances) -> _XSend SIGSEGV.
     * Render to a software image surface and commit with XPutImage, which is detoured
     * to xwp's own Xlib -- so every X call stays in the single static instance. */
    sf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, (int)W, (int)H);
#else
    sf = cairo_xlib_surface_create(d, win, DefaultVisual(d, DefaultScreen(d)), W, H);
#endif
    cr = cairo_create(sf);
    cairo_set_source_rgb(cr, 0.937, 0.937, 0.937);         /* flat trough */
    cairo_paint(cr);

    range = mx - mn;
    if (range <= 0) range = 1;
    vert    = (H >= W);
    breadth = vert ? W : H;
    arrow   = sa ? breadth : 0.0;                   /* reserve each arrow (~square) */
    start   = pad + arrow;                          /* trough start (past top arrow) */
    full    = (vert ? H : W) - 2 * pad - 2 * arrow; /* usable trough length */
    thick   = breadth - 2 * (pad + 1);              /* slimmer, centered pill */
    if (thick < 4) thick = 4;
    if (full < 4) full = 4;
    slen = ss * full / range;
    if (slen < 14 && full > 14) slen = 14;
    if (slen > full) slen = full;
    spos = start + (double)(val - mn) * full / range;
    if (spos + slen > start + full) spos = start + full - slen;
    if (spos < start) spos = start;
    /* Use the whole bar: at the extremes let the pill reach the physical ends,
     * covering the (paint-suppressed) arrow-button areas.  The drag mapping in
     * the middle is untouched, so tracking stays 1:1. */
    {
        double axis = vert ? H : W;
        double lo = spos, hi = spos + slen;
        if (val <= mn)      lo = pad;
        if (val >= mx - ss) hi = axis - pad;
        spos = lo;
        slen = hi - lo;
        if (slen < 8) slen = 8;
    }
    r = thick / 2;
    if (vert) rx_rounded_rect(cr, (breadth - thick) / 2, spos, thick, slen, r);
    else      rx_rounded_rect(cr, spos, (breadth - thick) / 2, slen, thick, r);
    if (rx_verbose)
        rx_log("sb %ux%u val=%d[%d..%d] ss=%d arrows=%d -> slen=%.0f",
               W, H, val, mn, mx, ss, (int)sa, slen);
    cairo_set_source_rgb(cr, 0.60, 0.63, 0.67);            /* rounded pill slider */
    cairo_fill(cr);
    cairo_surface_flush(sf);
#ifdef RX_STATIC81
    {   /* commit the rendered image straight to the window via XPutImage (static path) */
        unsigned char *data = cairo_image_surface_get_data(sf);
        int stride = cairo_image_surface_get_stride(sf);
        Visual *vis = DefaultVisual(d, DefaultScreen(d));
        XImage *xi = data ? XCreateImage(d, vis, 24, ZPixmap, 0, (char *)data, W, H, 32, stride) : 0;
        if (xi) {
            GC gc = XCreateGC(d, win, 0, 0);
            XPutImage(d, win, gc, xi, 0, 0, 0, 0, W, H);
            XFreeGC(d, gc);
            xi->data = 0;                                   /* cairo owns the pixels */
            XDestroyImage(xi);
        }
    }
#endif
    cairo_destroy(cr);
    cairo_surface_destroy(sf);
    XFlush(d);
    rx_in_my_draw = 0;
}

/* ------------------------------------------------------- custom buttons ----
 * Windowed XmPushButtons: own their pixels like scrollbars, capture the label
 * from Motif's text-draw call, and render a modern rounded button + AA text. */

#define RX_MAXBTN 2048     /* menu items persist for the app's life; a full WP UI has
                            * hundreds across all menus/submenus/toolbars/dialogs */
#define RX_KIND_TEXT 0
#define RX_KIND_DOWN 1
#define RX_KIND_UP   2
#define RX_GADGET_FS 13         /* fixed label font size for windowless dialog buttons */
#define RX_MENU_NORMAL  0       /* is_menu kind: plain item */
#define RX_MENU_CASCADE 1       /* has a submenu -> draw a chevron */
#define RX_MENU_TOGGLE  2       /* checkbox item -> draw a check box */
#define RX_OP_COPYAREA  1
#define RX_OP_COPYPLANE 2

/* One entry per windowed button we've taken over.  We OBSERVE the draw ops Motif
 * issues (text segments + icon blits), CLASSIFY (arrow / text / icon / plain),
 * and RENDER our modern version - deferred to a 0ms timeout so a whole draw cycle
 * (e.g. label + accelerator) is accumulated before we paint. */
struct rx_btn_s {
    Widget w;
    int    kind;                    /* name hint: TEXT / DOWN / UP */
    int    armed, dirty;
    int    t_stale, b_stale;        /* text/blit rendered -> next of that type resets */
    int    probed;                  /* tree-probe done once */
    int    is_gadget;               /* windowless XmPushButtonGadget - draws on parent win */
    int    is_menu;                 /* menu item - flat render, hover via enter/leave */
    int    is_toggle;               /* XmToggleButton - draw check box / radio + label */
    int    is_label;                /* XmLabel(Gadget) - crisp flat text, matching bg */
    int    is_frame;                /* XmFrame - draw a modern group box border */
    int    is_optbtn;               /* XmCascadeButtonGadget option menu - draw a down arrow */
    Pixmap bgpm;                    /* windowed items: our render kept as the window background */
    int    lx, ly, lw, lh;          /* last configured rect (parent coords) - to clear on move/resize */
    int    hovered;                 /* pointer is over this item (enter/leave) */
    Window pwin;                    /* gadget: parent window it's drawn onto */
    int    grx, gry, grw, grh;      /* gadget: real rect in pwin from Motif's shadow frame (grw>0=set) */
    int    font_asc, font_h;        /* metrics of Motif's actual label font (font_h>0 = known) */
    int    focused;                 /* Motif drew the highlight/location-cursor ring */
    int    focus_seen;              /* ring seen in the current accumulation cycle */
    int    have_hl;                 /* hlcolor resolved */
    unsigned long hlcolor;          /* XmNhighlightColor pixel of this button */
    int    nseg;
    struct { char s[80]; int x, y; } seg[6];
    int    nblit;
    struct { int op; Drawable src; GC gc; int sx, sy;
             unsigned int w, h; int dx, dy; unsigned long plane; } blit[6];
};
static struct rx_btn_s rx_btns[RX_MAXBTN];
static int rx_nbtn;
static XtAppContext rx_app;
static int rx_flush_pending;
static int (*rx_real_copyarea)(Display *, Drawable, Drawable, GC, int, int,
                               unsigned int, unsigned int, int, int);
static int (*rx_real_copyplane)(Display *, Drawable, Drawable, GC, int, int,
                                unsigned int, unsigned int, int, int, unsigned long);

static int rx_btn_index(Drawable dr)
{
    int i;
    for (i = 0; i < rx_nbtn; i++)
        if (rx_btns[i].w && !rx_btns[i].is_gadget && XtIsRealized(rx_btns[i].w) &&
            XtWindow(rx_btns[i].w) == (Window)dr)
            return i;
    return -1;
}

/* Rect of a gadget WITHIN its parent window.  Prefer the real rect captured from
 * Motif's own shadow frame (exact).  Until that's seen, derive the origin from
 * XtTranslateCoords (XmNx/XmNy are in a different coord space) and use the resource
 * size as a rough fallback (it can read ~2x, hence the enormous first frame). */
static int rx_gadget_rect(int slot, int *x, int *y, int *ww, int *hh)
{
    struct rx_btn_s *b = &rx_btns[slot];
    Widget w = b->w, par = XtParent(w);
    Dimension gw = 0, gh = 0;
    Position ax = 0, ay = 0, px = 0, py = 0;
    if (!par || !XtIsRealized(par)) return 0;
    XtTranslateCoords(w, 0, 0, &ax, &ay);       /* position: always current (survives resize) */
    XtTranslateCoords(par, 0, 0, &px, &py);
    *x = ax - px; *y = ay - py;
    if (b->grw > 0 && b->grh > 0) {
        int mh = b->grh, k;                     /* row buttons share height: use the tallest sibling */
        for (k = 0; k < rx_nbtn; k++)
            if (rx_btns[k].is_gadget && rx_btns[k].w && rx_btns[k].pwin == b->pwin && rx_btns[k].grh > mh)
                mh = rx_btns[k].grh;
        *ww = b->grw; *hh = mh;
    } else { XtVaGetValues(w, "width", &gw, "height", &gh, (char *)0); *ww = gw; *hh = gh; }  /* ~2x fallback */
    return *ww > 0 && *hh > 0;
}

/* Generous hit rect for ATTRIBUTION: translate position + the (over-large) XmN size,
 * so a label/shadow draw is never missed even before we've learned the real size. */
static int rx_gadget_hitrect(int slot, int *x, int *y, int *ww, int *hh)
{
    struct rx_btn_s *b = &rx_btns[slot];
    Widget w = b->w, par = XtParent(w);
    Dimension gw = 0, gh = 0; Position ax = 0, ay = 0, px = 0, py = 0;
    if (!par || !XtIsRealized(par)) return 0;
    XtVaGetValues(w, "width", &gw, "height", &gh, (char *)0);
    XtTranslateCoords(w, 0, 0, &ax, &ay);
    XtTranslateCoords(par, 0, 0, &px, &py);
    *x = ax - px; *y = ay - py; *ww = gw; *hh = gh;
    return gw > 0 && gh > 0;
}

/* Which hooked gadget (if any) owns point (x,y) on parent window w. */
static int rx_gadget_at(Window w, int x, int y)
{
    int i, gx, gy, gw, gh;
    for (i = 0; i < rx_nbtn; i++) {
        struct rx_btn_s *b = &rx_btns[i];
        if (!b->w || !b->is_gadget) continue;
        if (!XtIsManaged(b->w)) continue;                 /* hidden gadget (e.g. Help) - ignore */
        if (!b->pwin && XtIsRealized(XtParent(b->w))) b->pwin = XtWindow(XtParent(b->w));  /* lazy */
        if (b->pwin != w) continue;
        if (!rx_gadget_hitrect(i, &gx, &gy, &gw, &gh)) continue;
        if (gx == 0 && gy == 0) continue;                 /* not laid out yet - default rect */
        if (x >= gx && x < gx + gw && y >= gy && y < gy + gh)
            return i;
    }
    return -1;
}

/* A drawable whose Motif paint we suppress (scrollbar or hooked button). */
static int rx_is_owned_drawable(Drawable dr)
{
    if (rx_in_my_draw) return 0;
    if (rx_draw && rx_is_sb_drawable(dr)) return 1;
    if (rx_drawbtn && rx_btn_index(dr) >= 0) return 1;
    return 0;
}

static int rx_ignore_err(Display *d, XErrorEvent *e) { (void)d; (void)e; return 0; }

/* Recursively walk the whole window tree, computing absolute screen coords, and
 * log every VIEWABLE window that overlaps the target rect - to find a non-child
 * window (sibling/cousin/other top-level) stacked over our button. */
static void rx_walk(Display *d, Window w, int ax, int ay, int depth,
                    int bx, int by, int bw, int bh, Window self)
{
    Window root, parent, *kids = 0; unsigned int nk = 0, i;
    XWindowAttributes wa; int wx, wy, over;
    if (depth > 24) return;
    if (!XGetWindowAttributes(d, w, &wa)) return;
    wx = ax + wa.x; wy = ay + wa.y;                        /* absolute origin */
    over = !(wx + wa.width <= bx || wx >= bx + bw || wy + wa.height <= by || wy >= by + bh);
    if (over && wa.map_state == IsViewable && w != self) {
        Widget cw = XtWindowToWidget(d, w);
        rx_log("  OVL depth=%d 0x%lx %dx%d @abs %d,%d class=%s%s",
            depth, (unsigned long)w, wa.width, wa.height, wx, wy,
            cw ? rx_class(cw) : "(none)", (wa.your_event_mask ? "" : " [no-input]"));
    }
    if (XQueryTree(d, w, &root, &parent, &kids, &nk)) {
        for (i = 0; i < nk; i++) rx_walk(d, kids[i], wx, wy, depth + 1, bx, by, bw, bh, self);
        if (kids) XFree(kids);
    }
}
static void rx_probe_fulltree(Display *d, Window win, int bi)
{
    int (*old)(Display *, XErrorEvent *) = XSetErrorHandler(rx_ignore_err);
    Window root = DefaultRootWindow(d), child = 0;
    int bx = 0, by = 0, tx, ty;
    unsigned int bw = 0, bh = 0, bd; Window r; int wx, wy; unsigned int bbw;
    XGetGeometry(d, win, &r, &wx, &wy, &bw, &bh, &bbw, &bd);
    XTranslateCoordinates(d, win, root, 0, 0, &bx, &by, &child);
    tx = bx; ty = by;
    rx_log("FULLTREE btn %d win=0x%lx abs rect %ux%u @%d,%d - windows overlapping it:",
        bi, (unsigned long)win, bw, bh, tx, ty);
    rx_walk(d, root, 0, 0, 0, bx, by, (int)bw, (int)bh, win);
    XSetErrorHandler(old);
}

/* One-shot dump of a button window's neighbourhood: geometry, parent chain, its
 * own children, and its siblings' stacking + overlap - to find any window sitting
 * over the label that would hide our text (an overlay/virtual-button window). */
static void rx_probe_tree(Display *d, Window win, int bi)
{
    Window root, parent, *kids = 0;
    unsigned int nk = 0, i;
    int wx, wy; unsigned int ww = 0, wh = 0, bw, dep;
    int (*old)(Display *, XErrorEvent *) = XSetErrorHandler(rx_ignore_err);
    Window r; Widget pw;

    XGetGeometry(d, win, &r, &wx, &wy, &ww, &wh, &bw, &dep);
    rx_log("TREE btn %d win=0x%lx geom %ux%u @%d,%d depth=%u", bi, (unsigned long)win, ww, wh, wx, wy, dep);

    /* parent chain */
    {
        Window cur = win; int lvl;
        for (lvl = 0; lvl < 5; lvl++) {
            if (!XQueryTree(d, cur, &root, &parent, &kids, &nk)) break;
            if (kids) { XFree(kids); kids = 0; }
            pw = XtWindowToWidget(d, parent);
            rx_log("  parent[%d] 0x%lx class=%s", lvl, (unsigned long)parent, pw ? rx_class(pw) : "(none)");
            if (!parent || parent == root) break;
            cur = parent;
        }
    }
    /* our own children */
    if (XQueryTree(d, win, &root, &parent, &kids, &nk)) {
        rx_log("  win has %u child(ren)", nk);
        for (i = 0; i < nk; i++) {
            XWindowAttributes wa; Widget cw = XtWindowToWidget(d, kids[i]);
            if (XGetWindowAttributes(d, kids[i], &wa))
                rx_log("    child[%u] 0x%lx %dx%d @%d,%d map=%d class=%s",
                    i, (unsigned long)kids[i], wa.width, wa.height, wa.x, wa.y, wa.map_state,
                    cw ? rx_class(cw) : "(none)");
        }
        if (kids) { XFree(kids); kids = 0; }
    }
    /* siblings stacked ABOVE us that overlap our rect (parent's kids are bottom->top) */
    if (XQueryTree(d, win, &root, &parent, &kids, &nk)) {
        if (kids) { XFree(kids); kids = 0; }
        if (XQueryTree(d, parent, &root, &parent, &kids, &nk)) {
            int me = -1;
            for (i = 0; i < nk; i++) if (kids[i] == win) { me = (int)i; break; }
            rx_log("  parent has %u sibling(s); we are #%d", nk, me);
            for (i = (me >= 0 ? (unsigned)me + 1 : 0); i < nk; i++) {  /* above us */
                XWindowAttributes wa; Widget sw = XtWindowToWidget(d, kids[i]);
                if (XGetWindowAttributes(d, kids[i], &wa) && wa.map_state == IsViewable)
                    rx_log("    ABOVE 0x%lx %dx%d @%d,%d class=%s",
                        (unsigned long)kids[i], wa.width, wa.height, wa.x, wa.y,
                        sw ? rx_class(sw) : "(none)");
            }
        }
        if (kids) { XFree(kids); kids = 0; }
    }
    /* which window actually owns the label center point? */
    {
        Window child = 0; int tx, ty;
        if (XTranslateCoordinates(d, win, win, (int)ww / 2, (int)wh / 2, &tx, &ty, &child))
            rx_log("  window at label-center = 0x%lx (0=self, no child there)", (unsigned long)child);
    }
    XSetErrorHandler(old);
}

static void rx_bg_rgb(Widget w, double *r, double *g, double *bl);   /* fwd */

/* Vertical centre (in frame-window coords) of an XmFrame's title child, so the
 * group-box line runs THROUGH the title text.  -1 if there is no windowed title. */
static int rx_frame_title_center_y(Widget frame)
{
    WidgetList kids = 0; Cardinal n = 0, i;
    Display *d = XtDisplayOfObject(frame);
    Position fx = 0, fy = 0;
    if (!d) return -1;
    XtTranslateCoords(frame, 0, 0, &fx, &fy);
    XtVaGetValues(frame, "children", &kids, "numChildren", &n, (char *)0);
    for (i = 0; i < n && kids; i++) {
        unsigned char ct = 0;
        XtVaGetValues(kids[i], "childType", &ct, (char *)0);   /* XmFRAME_TITLE_CHILD = 2 */
        if (ct == 2 && XtIsRealized(kids[i]) && XtWindow(kids[i])) {
            Position tx = 0, ty = 0; Window r; int gx, gy; unsigned int gw, gh, bw, dep;
            XtTranslateCoords(kids[i], 0, 0, &tx, &ty);
            if (XGetGeometry(d, XtWindow(kids[i]), &r, &gx, &gy, &gw, &gh, &bw, &dep))
                return (ty - fy) + (int)gh / 2;
        }
    }
    return -1;
}

/* RENDER: classify from what we accumulated, then draw the modern button. */
static void rx_render_btn(int bi)
{
    struct rx_btn_s *b = &rx_btns[bi];
    Display *d = XtDisplayOfObject(b->w);
    Window win;
    int i, gx = 0, gy = 0;              /* commit offset within the target window */
    int sens;                          /* 0 = disabled (insensitive) -> render greyed */
    unsigned int W = 0, H = 0;
    cairo_surface_t *sf;
    cairo_t *cr;

    if (!rx_drawbtn || !d) return;
    sens = XtIsSensitive(b->w);
    if (b->is_gadget) {                 /* windowless: draw onto the parent at the gadget rect */
        win = b->pwin;
        if (!win) return;
        if (b->grw > 2 && b->grh > 2) { /* EXACT rect from Motif's clip - no overspill on resize */
            gx = b->grx; gy = b->gry; W = b->grw; H = b->grh;
        } else if (b->nseg >= 1) {      /* fallback: size from the label, centered on it */
            cairo_surface_t *ms = cairo_image_surface_create(CAIRO_FORMAT_RGB24, 8, 8);
            cairo_t *mc = cairo_create(ms);
            cairo_text_extents_t te;
            int tw, PADH = 14;
            double fs = b->font_h > 0 ? b->font_h : RX_GADGET_FS;   /* match Motif's label font size */
            int PADV = (int)fs;   /* full font-height per side -> H ~= 3*font_h, matches Motif's chrome */
            cairo_select_font_face(mc, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(mc, fs);
            cairo_text_extents(mc, b->seg[0].s, &te);
            tw = (int)(te.width + 0.5);
            W = tw + 2 * PADH;
            H = (int)fs + 2 * PADV;
            /* seg[0].x,y = ABSOLUTE baseline-left of Motif's label in pwin.  Motif centers
             * the label, so button-left = label-left - PADH; center button on the label box. */
            gx = b->seg[0].x - PADH;
            gy = (int)(b->seg[0].y + te.y_bearing + te.height / 2 - (double)H / 2 + 0.5);
            cairo_destroy(mc); cairo_surface_destroy(ms);
        } else {                        /* no label captured (icon/arrow gadget) - use rough rect */
            int rw, rh;
            if (!rx_gadget_rect(bi, &gx, &gy, &rw, &rh)) return;
            W = rw; H = rh;
        }
    } else {
        win = XtWindow(b->w);
        if (!win) return;
        if (!rx_win_size(b->w, win, &W, &H)) return;
    }
    if (b->is_optbtn) {                 /* combo: grow a few px to fully cover Motif's control */
        gx -= 3; gy -= 2; W += 6; H += 4;
    }
    if ((int)W < 2 || (int)H < 2) return;
    if (rx_verbose) rx_log("btn %d render %ux%u win=0x%lx@%d,%d kind=%d nseg=%d nblit=%d gadget=%d",
        bi, W, H, (unsigned long)win, gx, gy, b->kind, b->nseg, b->nblit, b->is_gadget);

    rx_in_my_draw = 1;

    /* Gadget moved/resized (no ConfigureNotify for windowless widgets) -> clear the
     * rect it vacated on the shared parent so our old paint there doesn't linger. */
    if (b->is_gadget && b->lw > 0 && (gx != b->lx || gy != b->ly || (int)W != b->lw || (int)H != b->lh))
        XClearArea(d, win, b->lx, b->ly, b->lw, b->lh, True);
    if (b->is_gadget) { b->lx = gx; b->ly = gy; b->lw = W; b->lh = H; }

    if (rx_debugfill) {                                  /* RETROXT_DEBUGFILL: test the XPutImage commit path */
        cairo_surface_t *ib = cairo_image_surface_create(CAIRO_FORMAT_RGB24, (int)W, (int)H);
        cairo_t *ic = cairo_create(ib);
        unsigned char *data; int stride; Visual *vis; XImage *xi;
        cairo_set_source_rgb(ic, 0.0, 0.0, 1.0);         /* solid BLUE buffer */
        cairo_paint(ic);
        cairo_surface_flush(ib);
        data = cairo_image_surface_get_data(ib);
        stride = cairo_image_surface_get_stride(ib);
        vis = DefaultVisual(d, DefaultScreen(d));
        xi = data ? XCreateImage(d, vis, 24, ZPixmap, 0, (char *)data, W, H, 32, stride) : 0;
        if (xi) {
            GC gc = XCreateGC(d, win, 0, 0);
            int r = XPutImage(d, win, gc, xi, 0, 0, 0, 0, W, H);
            if (rx_verbose) rx_log("btn %d DEBUG blue XPutImage rc=%d %ux%u stride=%d", bi, r, W, H, stride);
            XFreeGC(d, gc);
            xi->data = 0; XDestroyImage(xi);
        }
        cairo_destroy(ic); cairo_surface_destroy(ib);
        XFlush(d); rx_in_my_draw = 0;
        return;
    }

    /* Render the WHOLE button into a software image surface, then push it to the
     * window in ONE XPutImage.  Cairo's solid fills reach an xlib surface fine, but
     * its GLYPH commit path is unreliable under the DEEPBIND-isolated cairo (text
     * only flickered in on disarm).  Rasterizing to an image = glyphs land in RAM
     * with no X calls, and the single blit commits text atomically with the bg. */
    sf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, (int)W, (int)H);
    cr = cairo_create(sf);

    if (b->is_frame) {                                   /* group box: matching bg + rounded border */
        double r, g, bl, top;
        int tcy = rx_frame_title_center_y(b->w);         /* run the line through the title's middle */
        top = (tcy > 1) ? (double)tcy : 1.0;
        rx_bg_rgb(b->w, &r, &g, &bl);
        cairo_set_source_rgb(cr, r, g, bl); cairo_paint(cr);
        cairo_set_source_rgb(cr, 0.56, 0.58, 0.63);
        cairo_set_line_width(cr, 1.2);
        rx_rounded_rect(cr, 1.0, top, W - 2.0, H - 1.0 - top, 5);
        cairo_stroke(cr);
        goto rx_menu_committed;
    }

    if (b->is_label) {                                   /* crisp flat label, matching bg */
        double r, g, bl, fs = b->font_h > 0 ? b->font_h : H * 0.42;
        rx_bg_rgb(b->w, &r, &g, &bl);
        cairo_set_source_rgb(cr, r, g, bl); cairo_paint(cr);
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        if (b->nseg >= 1) {                              /* shrink-to-fit: our font is wider than Motif's */
            cairo_text_extents_t te; double avail = (double)W - b->seg[0].x - 3;
            cairo_set_font_size(cr, fs);
            cairo_text_extents(cr, b->seg[0].s, &te);
            if (avail > 4 && te.width > avail) fs *= (avail / te.width) * 0.98;
        }
        cairo_set_font_size(cr, fs);
        cairo_set_source_rgb(cr, sens ? 0.12 : 0.55, sens ? 0.12 : 0.55, sens ? 0.14 : 0.57);
        for (i = 0; i < b->nseg; i++) { cairo_move_to(cr, b->seg[i].x, b->seg[i].y); cairo_show_text(cr, b->seg[i].s); }
        goto rx_menu_committed;
    }

    if (b->is_toggle) {                                  /* check box / radio + label */
        double fs = b->font_h > 0 ? b->font_h : H * 0.42;
        double isz = fs * 1.05, ix = 3, iy = (H - isz) / 2, cxc = ix + isz / 2, cyc = iy + isz / 2;
        unsigned char itype = 2; Boolean set = 0; int radio;
        XtVaGetValues(b->w, "indicatorType", &itype, "set", &set, (char *)0);
        radio = (itype == 1);                            /* XmONE_OF_MANY = radio */
        cairo_set_source_rgb(cr, 0.909, 0.909, 0.909); cairo_paint(cr);    /* dialog bg */
        cairo_set_line_width(cr, 1.4);
        if (radio) {
            cairo_arc(cr, cxc, cyc, isz / 2, 0, 6.28318);
            cairo_set_source_rgb(cr, 0.99, 0.99, 1.0); cairo_fill_preserve(cr);
            cairo_set_source_rgb(cr, sens ? 0.45 : 0.62, 0.47, 0.50); cairo_stroke(cr);
            if (set) {
                cairo_arc(cr, cxc, cyc, isz * 0.27, 0, 6.28318);
                cairo_set_source_rgb(cr, sens ? 0.20 : 0.55, sens ? 0.45 : 0.57, sens ? 0.85 : 0.62); cairo_fill(cr);
            }
        } else {
            rx_rounded_rect(cr, ix, iy, isz, isz, 3);
            if (set) cairo_set_source_rgb(cr, sens ? 0.20 : 0.60, sens ? 0.45 : 0.62, sens ? 0.85 : 0.66);
            else     cairo_set_source_rgb(cr, 0.99, 0.99, 1.0);
            cairo_fill_preserve(cr);
            cairo_set_source_rgb(cr, sens ? 0.45 : 0.62, 0.47, 0.50); cairo_stroke(cr);
            if (set) {
                cairo_set_source_rgb(cr, 1, 1, 1); cairo_set_line_width(cr, 1.8);
                cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND); cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
                cairo_move_to(cr, ix + isz * 0.24, iy + isz * 0.52);
                cairo_line_to(cr, ix + isz * 0.42, iy + isz * 0.72);
                cairo_line_to(cr, ix + isz * 0.78, iy + isz * 0.28);
                cairo_stroke(cr);
            }
        }
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        {   /* shrink-to-fit: our Sans is a touch wider than Motif's font, and the window
             * is fixed to Motif's width - scale the label down so it never clips. */
            double fst = fs;
            if (b->nseg >= 1) {
                cairo_text_extents_t te;
                double avail = (double)W - b->seg[0].x - 2;
                cairo_set_font_size(cr, fst);
                cairo_text_extents(cr, b->seg[0].s, &te);
                if (avail > 4 && te.width > avail) fst *= avail / te.width;
            }
            cairo_set_font_size(cr, fst);
        }
        cairo_set_source_rgb(cr, sens ? 0.12 : 0.55, sens ? 0.12 : 0.55, sens ? 0.14 : 0.57);
        for (i = 0; i < b->nseg; i++) { cairo_move_to(cr, b->seg[i].x, b->seg[i].y); cairo_show_text(cr, b->seg[i].s); }
        goto rx_menu_committed;
    }

    if (b->is_menu) {                                    /* FLAT menu item: hover bg + crisp label */
        double fs = b->font_h > 0 ? b->font_h : RX_GADGET_FS;
        if (b->armed || b->hovered) cairo_set_source_rgb(cr, 0.80, 0.87, 0.97);  /* hover/active accent */
        else                        cairo_set_source_rgb(cr, 0.912, 0.912, 0.912);/* menu grey */
        cairo_paint(cr);
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, fs);
        if (sens) cairo_set_source_rgb(cr, 0.12, 0.12, 0.14);
        else      cairo_set_source_rgb(cr, 0.58, 0.58, 0.60);   /* disabled: greyed */
        for (i = 0; i < b->nseg; i++) {                  /* label (+accelerator) at Motif's positions */
            cairo_move_to(cr, b->seg[i].x, b->seg[i].y);
            cairo_show_text(cr, b->seg[i].s);
        }
        if (b->nseg > 0) {                               /* underline the mnemonic (shortcut) letter */
            KeySym mn = 0;
            XtVaGetValues(b->w, "mnemonic", &mn, (char *)0);
            if (mn) {
                const char *lbl = b->seg[0].s;
                int mc = (int)(mn & 0xFF), k, idx = -1;
                int mcl = (mc >= 'A' && mc <= 'Z') ? mc + 32 : mc;
                for (k = 0; lbl[k]; k++) {
                    int c = (unsigned char)lbl[k]; c = (c >= 'A' && c <= 'Z') ? c + 32 : c;
                    if (c == mcl) { idx = k; break; }
                }
                if (idx >= 0) {
                    char pre[80]; cairo_text_extents_t tpre, tch; char one[2];
                    if (idx > 79) idx = 79;
                    memcpy(pre, lbl, idx); pre[idx] = 0;
                    one[0] = lbl[idx]; one[1] = 0;
                    cairo_text_extents(cr, pre, &tpre);
                    cairo_text_extents(cr, one, &tch);
                    {
                        double ux = b->seg[0].x + tpre.x_advance;
                        double uy = b->seg[0].y + 1.5;
                        cairo_set_line_width(cr, 1.0);
                        cairo_move_to(cr, ux, uy);
                        cairo_line_to(cr, ux + tch.x_advance, uy);
                        cairo_stroke(cr);
                    }
                }
            }
        }
        if (b->kind == RX_MENU_CASCADE) {                /* submenu chevron at the right */
            double s = fs * 0.30, cx = W - fs * 0.75, cy = H / 2.0;
            cairo_set_source_rgb(cr, 0.30, 0.32, 0.36);
            cairo_set_line_width(cr, 1.4);
            cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
            cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
            cairo_move_to(cr, cx - s * 0.5, cy - s);
            cairo_line_to(cr, cx + s * 0.5, cy);
            cairo_line_to(cr, cx - s * 0.5, cy + s);
            cairo_stroke(cr);
        }
        if (b->kind == RX_MENU_TOGGLE) {                 /* checkbox at the left */
            Boolean set = 0; double bs = fs * 0.85, bx = 4, by = (H - bs) / 2;
            XtVaGetValues(b->w, "set", &set, (char *)0);
            rx_rounded_rect(cr, bx, by, bs, bs, 2);
            cairo_set_source_rgb(cr, 0.98, 0.98, 0.99); cairo_fill_preserve(cr);
            cairo_set_source_rgb(cr, 0.45, 0.47, 0.50); cairo_set_line_width(cr, 1.2); cairo_stroke(cr);
            if (set) {
                cairo_set_source_rgb(cr, 0.20, 0.45, 0.85);
                cairo_set_line_width(cr, 1.8);
                cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
                cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
                cairo_move_to(cr, bx + bs * 0.22, by + bs * 0.52);
                cairo_line_to(cr, bx + bs * 0.42, by + bs * 0.74);
                cairo_line_to(cr, bx + bs * 0.80, by + bs * 0.26);
                cairo_stroke(cr);
            }
        }
        if (b->focused) {                                /* keyboard-focus indicator: dotted inset ring */
            double dashes[2] = { 1.5, 1.5 };
            cairo_set_source_rgb(cr, 0.20, 0.30, 0.55);
            cairo_set_line_width(cr, 1.0);
            cairo_set_dash(cr, dashes, 2, 0);
            rx_rounded_rect(cr, 2.5, 2.5, W - 5.0, H - 5.0, 2);
            cairo_stroke(cr);
            cairo_set_dash(cr, dashes, 0, 0);
        }
        goto rx_menu_committed;
    }

    cairo_set_source_rgb(cr, 0.906, 0.906, 0.906);
    cairo_paint(cr);
    {
        double rad = (W < H ? W : H) * 0.30;
        if (rad > 6) rad = 6;
        if (rad < 2) rad = 2;
        rx_rounded_rect(cr, 1.5, 1.5, W - 3.0, H - 3.0, rad);
    }
    if (b->armed) cairo_set_source_rgb(cr, 0.80, 0.85, 0.94);
    else          cairo_set_source_rgb(cr, 0.975, 0.975, 0.985);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, 0.66, 0.69, 0.73);
    cairo_set_line_width(cr, 1.0);
    cairo_stroke(cr);

    if (b->kind != RX_KIND_TEXT) {                       /* CLASSIFY: arrow */
        double cx = W / 2.0, cy = H / 2.0, s = (W < H ? W : H) * 0.22;
        int up = (b->kind == RX_KIND_UP);
        if (s < 2.5) s = 2.5;
        cairo_set_source_rgb(cr, 0.24, 0.26, 0.30);
        cairo_set_line_width(cr, 1.6);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
        if (up) { cairo_move_to(cr, cx-s, cy+s*0.5); cairo_line_to(cr, cx, cy-s*0.5); cairo_line_to(cr, cx+s, cy+s*0.5); }
        else    { cairo_move_to(cr, cx-s, cy-s*0.5); cairo_line_to(cr, cx, cy+s*0.5); cairo_line_to(cr, cx+s, cy-s*0.5); }
        cairo_stroke(cr);
    } else if (b->nseg > 0) {                            /* CLASSIFY: text */
        double fs = b->is_gadget ? (b->font_h > 0 ? b->font_h : RX_GADGET_FS) : H * 0.42;
        if (!b->is_gadget) { if (fs > 15) fs = 15; if (fs < 9) fs = 9; }
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, fs);
        if (sens) cairo_set_source_rgb(cr, 0.13, 0.13, 0.13);
        else      cairo_set_source_rgb(cr, 0.58, 0.58, 0.60);   /* disabled: greyed */
        if (b->nseg == 1 || b->is_gadget) {              /* center a single label (gadgets: always) */
            cairo_text_extents_t te;
            cairo_text_extents(cr, b->seg[0].s, &te);
            if (rx_verbose) {
                int st = cairo_status(cr);
                rx_log("btn %d text '%s' extents w=%.1f h=%.1f xb=%.1f yb=%.1f status=%d(%s)",
                    bi, b->seg[0].s, te.width, te.height, te.x_bearing, te.y_bearing,
                    st, cairo_status_to_string ? cairo_status_to_string(st) : "?");
            }
            {   /* option buttons reserve the right side for the arrow; shrink the label
                 * to fit that space so it never overlaps the arrow. */
                double avail = (double)W;
                if (b->is_optbtn) { double as = (W < H ? W : H) * 0.16; avail = W - 2.0 * as - 8.0; if (avail < 12) avail = W; }
                if (te.width > avail && avail > 4) {
                    fs *= avail / te.width;
                    cairo_set_font_size(cr, fs);
                    cairo_text_extents(cr, b->seg[0].s, &te);
                }
                cairo_move_to(cr, (avail - te.width) / 2 - te.x_bearing,
                                  (H - te.height) / 2 - te.y_bearing);
            }
            cairo_show_text(cr, b->seg[0].s);
        } else {                                         /* keep Motif layout (label+accel) */
            for (i = 0; i < b->nseg; i++) {
                cairo_move_to(cr, b->seg[i].x, b->seg[i].y);
                cairo_show_text(cr, b->seg[i].s);
            }
        }
    }
    if (b->is_optbtn) {                                  /* option-menu / combo: down arrow at right */
        double s = (W < H ? W : H) * 0.16, cx = W - s - 7.0, cy = H / 2.0;
        if (s < 3) s = 3;
        cairo_set_source_rgb(cr, sens ? 0.30 : 0.58, sens ? 0.32 : 0.58, sens ? 0.36 : 0.60);
        cairo_set_line_width(cr, 1.6);
        cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
        cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
        cairo_move_to(cr, cx - s, cy - s * 0.5);
        cairo_line_to(cr, cx, cy + s * 0.5);
        cairo_line_to(cr, cx + s, cy - s * 0.5);
        cairo_stroke(cr);
    }
    if (b->focused) {                                    /* dotted inset focus ring */
        double dashes[2] = { 1.5, 1.5 };
        double rad = (W < H ? W : H) * 0.30; if (rad > 5) rad = 5; if (rad < 2) rad = 2;
        cairo_set_source_rgb(cr, 0.20, 0.22, 0.26);
        cairo_set_line_width(cr, 1.0);
        cairo_set_dash(cr, dashes, 2, 0);
        rx_rounded_rect(cr, 3.5, 3.5, W - 7.0, H - 7.0, rad);
        cairo_stroke(cr);
        cairo_set_dash(cr, dashes, 0, 0);               /* clear dash for later strokes */
    }
rx_menu_committed:
    cairo_surface_flush(sf);
    cairo_destroy(cr);
    /* Commit straight to the button window: image -> Pixmap -> XCopyArea -> window.
     * (The "text erased between renders" that first drove me to overlays was the
     * DUPLICATE hook - a second slot for the same window re-rendering grey over the
     * text via rx_real_copyarea, which bypasses draw-logging so it looked like an
     * invisible server clear.  With hook-dedup that's gone.)  bg=None stops the
     * server clearing the window to a solid background on expose. */
    {
        unsigned char *data = cairo_image_surface_get_data(sf);
        int stride = cairo_image_surface_get_stride(sf);
        Visual *vis = DefaultVisual(d, DefaultScreen(d));
        XImage *xi = data ? XCreateImage(d, vis, 24, ZPixmap, 0, (char *)data, W, H, 32, stride) : 0;
        if (xi) {
            Pixmap pm = XCreatePixmap(d, win, W, H, 24);
            GC gc = XCreateGC(d, pm, 0, 0);
            XPutImage(d, pm, gc, xi, 0, 0, 0, 0, W, H);             /* image -> pixmap */
            xi->data = 0;                                           /* cairo owns the pixels */
            XDestroyImage(xi);
#ifdef RX_STATIC81
            if (!rx_real_copyarea)  rx_real_copyarea  = orig_XCopyArea;
            if (!rx_real_copyplane) rx_real_copyplane = orig_XCopyPlane;
#else
            if (!rx_real_copyarea)  rx_real_copyarea  = (int (*)(Display *, Drawable, Drawable, GC, int, int, unsigned int, unsigned int, int, int))dlsym(RTLD_NEXT, "XCopyArea");
            if (!rx_real_copyplane) rx_real_copyplane = (int (*)(Display *, Drawable, Drawable, GC, int, int, unsigned int, unsigned int, int, int, unsigned long))dlsym(RTLD_NEXT, "XCopyPlane");
#endif
            /* CLASSIFY: icon - replay Motif's blits INTO the pixmap on our bg. */
            if (b->kind == RX_KIND_TEXT && b->nseg == 0 && b->nblit > 0) {
                for (i = 0; i < b->nblit; i++) {
                    if (b->blit[i].op == RX_OP_COPYAREA && rx_real_copyarea)
                        rx_real_copyarea(d, b->blit[i].src, pm, b->blit[i].gc, b->blit[i].sx,
                            b->blit[i].sy, b->blit[i].w, b->blit[i].h, b->blit[i].dx, b->blit[i].dy);
                    else if (b->blit[i].op == RX_OP_COPYPLANE && rx_real_copyplane)
                        rx_real_copyplane(d, b->blit[i].src, pm, b->blit[i].gc, b->blit[i].sx,
                            b->blit[i].sy, b->blit[i].w, b->blit[i].h, b->blit[i].dx, b->blit[i].dy, b->blit[i].plane);
                }
            }
            /* Leave the window's NATURAL background (the dialog grey) in place: on a
             * resize the server clears to grey (which matches) and our 0ms re-render
             * repaints the button - no bg=None stale pixels, no bg-pixmap tiling. */
            if (rx_real_copyarea)
                rx_real_copyarea(d, pm, win, gc, 0, 0, W, H, gx, gy);
            XFreePixmap(d, pm);
            XFreeGC(d, gc);
        }
    }
    cairo_surface_destroy(sf);
    XFlush(d);
    rx_in_my_draw = 0;
}

static void rx_flush_cb(XtPointer cd, XtIntervalId *id)
{
    int i;
    (void)cd; (void)id;
    rx_flush_pending = 0;
    for (i = 0; i < rx_nbtn; i++)
        if (rx_btns[i].w && rx_btns[i].dirty) {
            rx_btns[i].focused = rx_btns[i].focus_seen;   /* latch this cycle's focus state */
            rx_render_btn(i);
            rx_btns[i].dirty = 0;
            rx_btns[i].t_stale = 1;      /* keep text/blit until that TYPE is redrawn */
            rx_btns[i].b_stale = 1;
            rx_btns[i].focus_seen = 0;   /* re-detect next cycle (a redraw w/o ring = focus lost) */
        }
}
static void rx_btn_schedule(Widget w)
{
    if (rx_flush_pending) return;
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    if (!rx_app) return;
    XtAppAddTimeOut(rx_app, 0, rx_flush_cb, (XtPointer)0);
    rx_flush_pending = 1;
}

/* OBSERVE: accumulate a draw op.  Text and blits reset INDEPENDENTLY at the start
 * of their own next cycle - so a blit-only redraw never wipes the captured label
 * (we keep a button's text and render it until fresh text replaces it). */
static void rx_btn_text(int bi, const char *s, int len, int x, int y)
{
    struct rx_btn_s *b = &rx_btns[bi];
    int i, n = 0;
    if (b->t_stale) { b->nseg = 0; b->t_stale = 0; }
    if (b->nseg >= 6) return;
    for (i = 0; i < len && n < 79; i++)
        if ((unsigned char)s[i] >= 32) b->seg[b->nseg].s[n++] = s[i];
    b->seg[b->nseg].s[n] = 0;
    if (!n) return;
    b->seg[b->nseg].x = x; b->seg[b->nseg].y = y;
    if (rx_verbose) rx_log("btn %d +text[%d] '%s' @%d,%d", bi, b->nseg, b->seg[b->nseg].s, x, y);
    b->nseg++;
    b->dirty = 1;
    rx_btn_schedule(b->w);
}
static void rx_btn_blit(int bi, int op, Drawable src, GC gc, int sx, int sy,
                        unsigned int w, unsigned int h, int dx, int dy, unsigned long plane)
{
    struct rx_btn_s *b = &rx_btns[bi];
    if (b->b_stale) { b->nblit = 0; b->b_stale = 0; }
    if (b->nblit >= 6) return;
    b->blit[b->nblit].op = op; b->blit[b->nblit].src = src; b->blit[b->nblit].gc = gc;
    b->blit[b->nblit].sx = sx; b->blit[b->nblit].sy = sy;
    b->blit[b->nblit].w = w;   b->blit[b->nblit].h = h;
    b->blit[b->nblit].dx = dx; b->blit[b->nblit].dy = dy; b->blit[b->nblit].plane = plane;
    b->nblit++;
    b->dirty = 1;
    rx_btn_schedule(b->w);
}

static void rx_btn_evh(Widget w, XtPointer cd, XEvent *ev, Boolean *cont)
{
    int bi = (int)(long)cd;
    (void)w; (void)cont;
    if (ev->type == ConfigureNotify) {
        struct rx_btn_s *b = &rx_btns[bi];
        int nx = ev->xconfigure.x, ny = ev->xconfigure.y;
        int nw = ev->xconfigure.width, nh = ev->xconfigure.height;
        rx_geom_set(ev->xconfigure.window, nw, nh);
        /* button moved/shrank -> clear the area it vacated in the parent, or our old
         * (larger) render lingers there (WP doesn't always repaint the parent). */
        if (b->lw > 0 && (nx != b->lx || ny != b->ly || nw != b->lw || nh != b->lh)) {
            Widget par = XtParent(b->w);
            if (par && XtIsRealized(par)) {
                int (*rc)(Display *, Window, int, int, unsigned int, unsigned int, Bool) =
#ifdef RX_STATIC81
                    orig_XClearArea;
#else
                    (int (*)(Display *, Window, int, int, unsigned int, unsigned int, Bool))dlsym(RTLD_NEXT, "XClearArea");
#endif
                if (rc) rc(XtDisplayOfObject(par), XtWindow(par), b->lx, b->ly, b->lw, b->lh, True);
            }
        }
        b->lx = nx; b->ly = ny; b->lw = nw; b->lh = nh;
    }
    if (ev->type == Expose && ev->xexpose.count > 0) return;
    rx_btns[bi].dirty = 1;
    rx_btn_schedule(rx_btns[bi].w);
}
static void rx_btn_arm(Widget w, XtPointer cd, XtPointer cb)
{
    int bi = (int)(long)cd; (void)w; (void)cb;
    rx_btns[bi].armed = 1; rx_btns[bi].dirty = 1; rx_btn_schedule(rx_btns[bi].w);
}
static void rx_btn_disarm(Widget w, XtPointer cd, XtPointer cb)
{
    int bi = (int)(long)cd; (void)w; (void)cb;
    rx_btns[bi].armed = 0; rx_btns[bi].dirty = 1; rx_btn_schedule(rx_btns[bi].w);
}
/* Menu item hover: pointer enter/leave drives the highlight + re-render. */
static void rx_menuitem_cross(Widget w, XtPointer cd, XEvent *ev, Boolean *cont)
{
    int bi = (int)(long)cd, i; (void)w; (void)cont;
    if (ev->type == EnterNotify) {
        for (i = 0; i < rx_nbtn; i++)   /* single highlight - a menu grab can eat Leave, so clear the rest here */
            if (i != bi && rx_btns[i].w && rx_btns[i].is_menu && (rx_btns[i].hovered || rx_btns[i].armed)) {
                rx_btns[i].hovered = 0; rx_btns[i].armed = 0;
                rx_btns[i].dirty = 1; rx_btn_schedule(rx_btns[i].w);
            }
        rx_btns[bi].hovered = 1;
    } else if (ev->type == LeaveNotify) {
        rx_btns[bi].hovered = 0;
    } else return;
    rx_btns[bi].dirty = 1; rx_btn_schedule(rx_btns[bi].w);
}
static void rx_btn_destroy(Widget w, XtPointer cd, XtPointer cb)
{
    int bi = (int)(long)cd; (void)cb;
    if (bi >= 0 && bi < rx_nbtn) {
        if (rx_btns[bi].bgpm) { Display *d = XtDisplayOfObject(w); if (d) XFreePixmap(d, rx_btns[bi].bgpm); rx_btns[bi].bgpm = 0; }
        rx_btns[bi].w = 0;
    }
}

static void rx_hook_button(Widget w, int kind)
{
    int i, slot = -1;
    if (!rx_drawbtn) return;
    if (rx_in_menu(w)) return;                   /* leave menu items entirely to Motif */
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;   /* already hooked - no duplicate overlay */
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d) - new widgets fall back to Motif", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w;
    rx_btns[slot].kind = kind;
    if (rx_verbose) rx_log("hook btn %d '%s' kind=%d", slot, XtName(w) ? XtName(w) : "", kind);
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_btn_evh, (XtPointer)(long)slot);
    XtAddCallback(w, "armCallback",     rx_btn_arm,     (XtPointer)(long)slot);
    XtAddCallback(w, "disarmCallback",  rx_btn_disarm,  (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback", rx_btn_destroy, (XtPointer)(long)slot);
}

/* Windowless gadget (XmPushButtonGadget): no window of its own - Motif draws it
 * onto the PARENT window at the gadget's (x,y).  We attribute draws by coordinate
 * and render into the parent at that offset.  Arm/disarm still fire as callbacks. */
static void rx_hook_gadget(Widget w, int kind)
{
    int i, slot = -1;
    Widget parent;
    if (!rx_drawbtn) return;
    if (rx_in_menu(w)) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    parent = XtParent(w);
    if (!parent) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d) - new widgets fall back to Motif", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w;
    rx_btns[slot].kind = kind;
    rx_btns[slot].is_gadget = 1;
    rx_btns[slot].pwin = XtIsRealized(parent) ? XtWindow(parent) : 0;   /* else resolved lazily */
    if (rx_verbose) rx_log("hook gadget %d '%s' kind=%d pwin=0x%lx", slot, XtName(w) ? XtName(w) : "", kind, (unsigned long)rx_btns[slot].pwin);
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddCallback(w, "armCallback",     rx_btn_arm,     (XtPointer)(long)slot);
    XtAddCallback(w, "disarmCallback",  rx_btn_disarm,  (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback", rx_btn_destroy, (XtPointer)(long)slot);
}

/* Menu item that is a GADGET (windowless XmCascadeButtonGadget / XmToggleButtonGadget /
 * XmPushButtonGadget - common in dialog menus, e.g. the File Open dialog).  Like
 * rx_hook_gadget but flagged is_menu so it draws the flat menu look (crisp label, hover,
 * submenu chevron for cascade, checkbox for toggle) and honours XtIsSensitive (greyed when
 * disabled).  Windowless -> NO XtAddEventHandler (that derefs a bogus Display and crashes);
 * rendering is driven by intercepting Motif's menu paint (rx_gadget_at). */
static void rx_hook_menu_gadget(Widget w, int kind)
{
    int i, slot = -1;
    Widget parent;
    if (!rx_drawbtn) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    parent = XtParent(w);
    if (!parent) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d) - new widgets fall back to Motif", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w;
    rx_btns[slot].kind = kind;
    rx_btns[slot].is_gadget = 1;
    rx_btns[slot].is_menu = 1;
    rx_btns[slot].pwin = XtIsRealized(parent) ? XtWindow(parent) : 0;   /* else resolved lazily */
    if (rx_verbose) rx_log("hook menu-gadget %d '%s' kind=%d pwin=0x%lx", slot, XtName(w) ? XtName(w) : "", kind, (unsigned long)rx_btns[slot].pwin);
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddCallback(w, "armCallback",       rx_btn_arm,     (XtPointer)(long)slot);
    XtAddCallback(w, "disarmCallback",    rx_btn_disarm,  (XtPointer)(long)slot);
    XtAddCallback(w, "cascadingCallback", rx_btn_arm,     (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback",   rx_btn_destroy, (XtPointer)(long)slot);
}

/* A widget's background colour as cairo RGB (so our fills blend with the dialog). */
static void rx_bg_rgb(Widget w, double *r, double *g, double *bl)
{
    Pixel px = 0; XColor c; Display *d = XtDisplayOfObject(w);
    *r = 0.909; *g = 0.909; *bl = 0.909;
    if (!d) return;
    XtVaGetValues(w, "background", &px, (char *)0);
    c.pixel = px;
    XQueryColor(d, DefaultColormap(d, DefaultScreen(d)), &c);
    *r = c.red / 65535.0; *g = c.green / 65535.0; *bl = c.blue / 65535.0;
}
/* Windowed XmLabel: crisp flat label in our normal-weight font (WP draws labels bold). */
static void rx_hook_label(Widget w)
{
    int i, slot = -1;
    if (!rx_drawbtn) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d)", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w; rx_btns[slot].is_label = 1;
    if (rx_verbose) rx_log("hook label %d '%s'", slot, XtName(w) ? XtName(w) : "");
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_btn_evh, (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback", rx_btn_destroy, (XtPointer)(long)slot);
}
/* XmFrame: draw a modern group-box border (suppress Motif's etched frame). */
static void rx_hook_frame(Widget w)
{
    int i, slot = -1;
    if (!rx_drawbtn) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d)", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w; rx_btns[slot].is_frame = 1;
    if (rx_verbose) rx_log("hook frame %d '%s'", slot, XtName(w) ? XtName(w) : "");
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_btn_evh, (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback", rx_btn_destroy, (XtPointer)(long)slot);
}

/* Re-render a toggle when its checked state changes (or it's re-sensitised). */
static void rx_toggle_changed(Widget w, XtPointer cd, XtPointer cb)
{
    int bi = (int)(long)cd; (void)w; (void)cb;
    rx_btns[bi].dirty = 1; rx_btn_schedule(rx_btns[bi].w);
}
/* Windowed XmToggleButton: draw a modern check box / radio + crisp label. */
static void rx_hook_toggle(Widget w)
{
    int i, slot = -1;
    if (!rx_drawbtn) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d) - new widgets fall back to Motif", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w;
    rx_btns[slot].is_toggle = 1;
    if (rx_verbose) rx_log("hook toggle %d '%s'", slot, XtName(w) ? XtName(w) : "");
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_btn_evh, (XtPointer)(long)slot);
    XtAddEventHandler(w, EnterWindowMask | LeaveWindowMask, False, rx_menuitem_cross, (XtPointer)(long)slot);
    XtAddCallback(w, "valueChangedCallback", rx_toggle_changed, (XtPointer)(long)slot);
    XtAddCallback(w, "destroyCallback",      rx_btn_destroy,    (XtPointer)(long)slot);
}

/* Windowed menu item: capture its label (+accelerator) and render it flat with our
 * crisp font; hover via enter/leave.  kind = normal / cascade (submenu) / toggle. */
static void rx_hook_menuitem(Widget w, int kind)
{
    int i, slot = -1;
    const char *cls;
    if (!rx_drawbtn) return;
    /* Menu items can be GADGETS (XmCascadeButtonGadget / XmToggleButtonGadget - common in
     * dialog option menus, e.g. the File Open dialog).  Gadgets are windowless RectObj
     * subclasses: XtAddEventHandler below would fetch a Display off a non-widget layout and
     * deref garbage -> SIGSEGV (in XSelectInput, on both 8.0 and 8.1).  Our expose-driven
     * render needs a real window anyway, so leave gadget menu items to Motif. */
    cls = rx_class(w);
    if (cls && strstr(cls, "Gadget")) return;
    for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) return;
    for (i = 0; i < rx_nbtn; i++) if (!rx_btns[i].w) { slot = i; break; }
    if (slot < 0 && rx_nbtn < RX_MAXBTN) slot = rx_nbtn++;
    if (slot < 0) { static int warned; if (!warned) { warned = 1; rx_log("WARNING: rx_btns full (%d) - new widgets fall back to Motif", RX_MAXBTN); } return; }
    memset(&rx_btns[slot], 0, sizeof rx_btns[slot]);
    rx_btns[slot].w = w;
    rx_btns[slot].kind = kind;
    rx_btns[slot].is_menu = 1;
    if (rx_verbose) rx_log("hook menuitem %d '%s' kind=%d", slot, XtName(w) ? XtName(w) : "", kind);
    if (!rx_app) rx_app = XtWidgetToApplicationContext(w);
    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_btn_evh, (XtPointer)(long)slot);
    XtAddEventHandler(w, EnterWindowMask | LeaveWindowMask, False, rx_menuitem_cross, (XtPointer)(long)slot);
    XtAddCallback(w, "armCallback",     rx_btn_arm,     (XtPointer)(long)slot);  /* menu open = active */
    XtAddCallback(w, "disarmCallback",  rx_btn_disarm,  (XtPointer)(long)slot);
    XtAddCallback(w, "cascadingCallback", rx_btn_arm,   (XtPointer)(long)slot);  /* cascade posting */
    XtAddCallback(w, "destroyCallback", rx_btn_destroy, (XtPointer)(long)slot);
}

/* Diagnostic: resolve the target window to a widget and log the draw op, so we
 * can see how every kind of button/label actually renders (windowed vs gadget,
 * text vs icon, how many text segments).  RETROXT_LOGDRAW=1. */
static void rx_ld(const char *op, Display *d, Drawable dr, const char *s, int len, int x, int y)
{
    Widget w;
    const char *cls, *nm;
    /* Always trace every draw hitting a hooked button window (tagged by index),
     * so we can reconstruct the full paint sequence for one button. */
    if (rx_verbose) {
        int bi = rx_drawbtn ? rx_btn_index((Window)dr) : -1;
        if (bi >= 0) {
            if (s && len > 0) {
                char tb[64]; int i, n = 0;
                for (i = 0; i < len && n < 63; i++) tb[n++] = ((unsigned char)s[i] >= 32) ? s[i] : '.';
                tb[n] = 0;
                rx_log("  DRAW btn %d %-11s @%d,%d '%s'%s", bi, op, x, y, tb, rx_in_my_draw ? " MINE" : "");
            } else {
                rx_log("  DRAW btn %d %-11s @%d,%d%s", bi, op, x, y, rx_in_my_draw ? " MINE" : "");
            }
        }
    }
    if (!rx_logdraw) return;
    w = XtWindowToWidget(d, (Window)dr);
    cls = w ? rx_class(w) : "(no-widget)";
    /* non-text shape ops: only log button-ish widgets, or it floods with bg fills */
    if (!s && !strstr(cls, "Button") && !strstr(cls, "Cascade") && !strstr(cls, "Arrow"))
        return;
    nm  = (w && XtName(w)) ? XtName(w) : "";
    if (s && len > 0) {
        char b[64];
        int i, n = 0;
        for (i = 0; i < len && n < 63; i++) b[n++] = ((unsigned char)s[i] >= 32) ? s[i] : '.';
        b[n] = 0;
        rx_log("%-11s %-20s name='%s' @%d,%d text='%s'", op, cls, nm, x, y, b);
    } else {
        rx_log("%-11s %-20s name='%s' win=0x%lx", op, cls, nm, (unsigned long)dr);
    }
}

/* Render one XmList row's text with our crisp monospace font (keeps the column
 * alignment) over a matching background; commit via pixmap->XCopyArea with Motif's
 * clip so partial rows never overspill.  Returns 1 if handled (Motif's text dropped). */
static int rx_list_text(Display *d, Window win, GC gc, int x, int y, const char *s, int len)
{
    XGCValues gv; XFontStruct *fx = 0;
    int selected, asc = 12, dsc = 4, fh, iw, ih, i, n = 0;
    char buf[512];
    cairo_surface_t *sf; cairo_t *cr; cairo_text_extents_t te;
    if (!rx_cairo_ok || !rx_skin) return 0;
    if (!XGetGCValues(d, gc, GCForeground | GCFont, &gv)) return 0;
    selected = (gv.foreground & 0xFFFFFF) >= 0x808080;      /* white text = selected row */
    if (gv.font) { fx = XQueryFont(d, gv.font); if (fx) { asc = fx->ascent; dsc = fx->descent; } }
    fh = asc + dsc; if (fh < 6) fh = 12;
    for (i = 0; i < len && n < 511; i++) buf[n++] = (unsigned char)s[i] >= 32 ? s[i] : ' ';
    buf[n] = 0;
    ih = fh + 3;
    rx_in_my_draw = 1;
    sf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, 8, 8);
    cr = cairo_create(sf);
    cairo_select_font_face(cr, "Monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, (double)fh);
    cairo_text_extents(cr, buf, &te);
    iw = (int)(te.width + 2); if (iw < 1) iw = 1;
    cairo_destroy(cr); cairo_surface_destroy(sf);

    sf = cairo_image_surface_create(CAIRO_FORMAT_RGB24, iw, ih);
    cr = cairo_create(sf);
    if (selected) cairo_set_source_rgb(cr, 0.227, 0.482, 0.835);
    else          cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);
    cairo_select_font_face(cr, "Monospace", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, (double)fh);
    if (selected) cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    else          cairo_set_source_rgb(cr, 0.10, 0.10, 0.12);
    cairo_move_to(cr, 0, asc);
    cairo_show_text(cr, buf);
    cairo_surface_flush(sf);
    {
        unsigned char *data = cairo_image_surface_get_data(sf);
        int stride = cairo_image_surface_get_stride(sf);
        Visual *vis = DefaultVisual(d, DefaultScreen(d));
        XImage *xi = data ? XCreateImage(d, vis, 24, ZPixmap, 0, (char *)data, iw, ih, 32, stride) : 0;
        if (xi) {
            Pixmap pm = XCreatePixmap(d, win, iw, ih, 24);
            GC pgc = XCreateGC(d, pm, 0, 0);
#ifdef RX_STATIC81
            if (!rx_real_copyarea) rx_real_copyarea = orig_XCopyArea;
#else
            if (!rx_real_copyarea) rx_real_copyarea = (int (*)(Display *, Drawable, Drawable, GC, int, int, unsigned int, unsigned int, int, int))dlsym(RTLD_NEXT, "XCopyArea");
#endif
            XPutImage(d, pm, pgc, xi, 0, 0, 0, 0, iw, ih);
            XCopyGC(d, gc, GCClipXOrigin | GCClipYOrigin | GCClipMask, pgc);   /* clip to the viewport */
            if (rx_real_copyarea) rx_real_copyarea(d, pm, win, pgc, 0, 0, iw, ih, x, y - asc);
            XFreeGC(d, pgc); XFreePixmap(d, pm);
            xi->data = 0; XDestroyImage(xi);
        }
    }
    cairo_destroy(cr); cairo_surface_destroy(sf);
    if (fx) XFreeFontInfo(NULL, fx, 1);
    rx_in_my_draw = 0;
    return 1;
}

/* Observe how XmList draws itself (items / selection / focus) - RETROXT_TRACE only. */
static void rx_listlog(const char *op, Display *d, Drawable dr, GC gc, int x, int y, unsigned int w, unsigned int h, const char *s, int len)
{
    XGCValues gv; char tb[64]; int i, n = 0; Widget wd; const char *wc;
    if (!rx_verbose || rx_in_my_draw) return;
    wd = XtWindowToWidget(d, (Window)dr);
    if (!wd) return;
    wc = rx_class(wd);
    if (strcmp(wc, "XmList") != 0 && strcmp(wc, "XiCombinationBox") != 0) return;
    if (!XGetGCValues(d, gc, GCForeground | GCBackground | GCLineStyle | GCFillStyle, &gv)) return;
    if (s && len > 0) { for (i = 0; i < len && n < 63; i++) tb[n++] = ((unsigned char)s[i] >= 32) ? s[i] : '.'; tb[n] = 0; }
    else tb[0] = 0;
    rx_log("  LIST %-11s @%d,%d %ux%u fg=%lu bg=%lu line=%d fill=%d '%s'",
        op, x, y, w, h, gv.foreground, gv.background, gv.line_style, gv.fill_style, tb);
}

/* Drop Motif's own scrollbar/button painting so only our Cairo rendering shows -
 * no flicker, no stale Motif look on first paint / resize.  Only requests to one
 * of OUR windows are dropped; every other draw passes straight through. */
int XFillRectangle(Display *d, Drawable dr, GC gc, int x, int y, unsigned int w, unsigned int h)
{
    REAL(XFillRectangle);
    if (!rx_in_my_draw) { rx_ld("XFillRect", d, dr, 0, 0, x, y); rx_listlog("FillRect", d, dr, gc, x, y, w, h, 0, 0);
        /* XmList selection = an inverted (dark) row fill; repaint it with our accent. */
        if (rx_skin && rx_pal_ready) {
            Widget wd = XtWindowToWidget(d, (Window)dr);
            if (wd && !strcmp(rx_class(wd), "XmList")) {
                XGCValues gv;
                if (XGetGCValues(d, gc, GCForeground, &gv) && (gv.foreground & 0xFFFFFF) < 0x808080) {
                    static GC selgc;
                    if (!selgc) selgc = XCreateGC(d, dr, 0, 0);
                    XCopyGC(d, gc, GCClipXOrigin | GCClipYOrigin | GCClipMask, selgc); /* same clip -> no overspill */
                    XSetForeground(d, selgc, rx_cAccent);
                    real_XFillRectangle(d, dr, selgc, x, y, w, h);
                    return 0;                                  /* suppress the black fill */
                }
            }
        }
    }
    if (rx_is_owned_drawable(dr)) return 0;
    if (!rx_in_my_draw && rx_drawbtn && rx_gadget_at((Window)dr, x, y) >= 0) return 0;  /* gadget face */
    return real_XFillRectangle(d, dr, gc, x, y, w, h);
}
int XDrawSegments(Display *d, Drawable dr, GC gc, XSegment *s, int n)
{
    REAL(XDrawSegments);
    if (!rx_in_my_draw) { rx_ld("XDrawSegs", d, dr, 0, 0, n > 0 ? s[0].x1 : 0, n > 0 ? s[0].y1 : 0);
        rx_listlog("DrawSegs", d, dr, gc, n>0?s[0].x1:0, n>0?s[0].y1:0, n, 0, 0, 0);
        /* XmList: kill the whole-list dashed focus box that appears when the location
         * cursor item scrolls out of view (a tall dashed rect); keep the per-item one. */
        if (rx_skin && n > 0) {
            Widget wd = XtWindowToWidget(d, (Window)dr);
            if (wd && !strcmp(rx_class(wd), "XmList")) {
                XGCValues gv;
                if (XGetGCValues(d, (GC)gc, GCLineStyle, &gv) && gv.line_style != LineSolid) {
                    int k, miny = s[0].y1, maxy = s[0].y1;
                    for (k = 0; k < n; k++) {
                        if (s[k].y1 < miny) miny = s[k].y1;
                        if (s[k].y2 < miny) miny = s[k].y2;
                        if (s[k].y1 > maxy) maxy = s[k].y1;
                        if (s[k].y2 > maxy) maxy = s[k].y2;
                    }
                    if (maxy - miny > 40) return 0;        /* whole-list box -> drop */
                }
            }
        }
    }
    if (rx_is_owned_drawable(dr)) return 0;
    if (!rx_in_my_draw && rx_drawbtn && n > 0 && rx_gadget_at((Window)dr, s[0].x1, s[0].y1) >= 0) return 0;  /* gadget shadow */
    return real_XDrawSegments(d, dr, gc, s, n);
}
int XDrawLines(Display *d, Drawable dr, GC gc, XPoint *p, int n, int mode)
{
    REAL(XDrawLines);
    if (!rx_in_my_draw) { rx_ld("XDrawLines", d, dr, 0, 0, n > 0 ? p[0].x : 0, n > 0 ? p[0].y : 0);
        rx_listlog("DrawLines", d, dr, gc, n>0?p[0].x:0, n>0?p[0].y:0, n, 0, 0, 0); }
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawLines(d, dr, gc, p, n, mode);
}
int XFillPolygon(Display *d, Drawable dr, GC gc, XPoint *p, int n, int shape, int mode)
{
    REAL(XFillPolygon);
    if (!rx_in_my_draw) rx_ld("XFillPoly", d, dr, 0, 0, n > 0 ? p[0].x : 0, n > 0 ? p[0].y : 0);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XFillPolygon(d, dr, gc, p, n, shape, mode);
}
int XCopyArea(Display *d, Drawable src, Drawable dst, GC gc, int sx, int sy,
              unsigned int w, unsigned int h, int dx, int dy)
{
    int bi;
    REAL(XCopyArea);
    if (!rx_in_my_draw) {
        rx_ld("XCopyArea", d, dst, 0, 0, dx, dy);
        bi = rx_drawbtn ? rx_btn_index(dst) : -1;
        if (bi >= 0) { rx_btn_blit(bi, RX_OP_COPYAREA, src, gc, sx, sy, w, h, dx, dy, 0); return 0; }
        if (rx_draw && rx_is_sb_drawable(dst)) return 0;
    }
    return real_XCopyArea(d, src, dst, gc, sx, sy, w, h, dx, dy);
}
int XClearArea(Display *d, Window win, int x, int y, unsigned int w, unsigned int h, Bool exp)
{
    REAL(XClearArea);
    if (!rx_in_my_draw) { int bi = rx_drawbtn ? rx_btn_index(win) : -1;
        if (bi >= 0) rx_log("WIPE XClearArea btn %d %d,%d %ux%u exp=%d", bi, x, y, w, h, exp); }
    if (rx_is_owned_drawable(win)) return 0;
    return real_XClearArea(d, win, x, y, w, h, exp);
}
int XClearWindow(Display *d, Window win)
{
    REAL(XClearWindow);
    if (!rx_in_my_draw) { int bi = rx_drawbtn ? rx_btn_index(win) : -1;
        if (bi >= 0) rx_log("WIPE XClearWindow btn %d", bi); }
    if (rx_is_owned_drawable(win)) return 0;   /* would wipe our rendering */
    return real_XClearWindow(d, win);
}
/* Stop the SERVER from auto-clearing an owned window to its background on every
 * expose/redraw (that silently wiped our text - not an interceptable request).
 * Force background_pixmap=None so we own 100% of the pixels. */
int XSetClipRectangles(Display *d, GC gc, int cx, int cy, XRectangle *r, int n, int ordering)
{
    REAL(XSetClipRectangles);
    if (n >= 1) {   /* bounding box of the clip rects, offset by the clip origin */
        int k, minx = r[0].x, miny = r[0].y, maxx = r[0].x + r[0].width, maxy = r[0].y + r[0].height;
        for (k = 1; k < n; k++) {
            if (r[k].x < minx) minx = r[k].x;
            if (r[k].y < miny) miny = r[k].y;
            if (r[k].x + r[k].width  > maxx) maxx = r[k].x + r[k].width;
            if (r[k].y + r[k].height > maxy) maxy = r[k].y + r[k].height;
        }
        rx_clip_store(gc, cx + minx, cy + miny, maxx - minx, maxy - miny);
    } else rx_clip_none(gc);
    return real_XSetClipRectangles(d, gc, cx, cy, r, n, ordering);
}
int XSetClipMask(Display *d, GC gc, Pixmap pm)
{
    REAL(XSetClipMask);
    if (pm == None) rx_clip_none(gc);
    return real_XSetClipMask(d, gc, pm);
}
int XSetWindowBackgroundPixmap(Display *d, Window win, Pixmap pm)
{
    REAL(XSetWindowBackgroundPixmap);
    return real_XSetWindowBackgroundPixmap(d, win, pm);
}
int XSetWindowBackground(Display *d, Window win, unsigned long pixel)
{
    REAL(XSetWindowBackground);
    return real_XSetWindowBackground(d, win, pixel);
}
int XDrawRectangle(Display *d, Drawable dr, GC gc, int x, int y, unsigned int w, unsigned int h)
{
    REAL(XDrawRectangle);
    if (!rx_in_my_draw) rx_listlog("DrawRect", d, dr, gc, x, y, w, h, 0, 0);
    if (!rx_in_my_draw && rx_verbose) { int bi = rx_drawbtn ? rx_btn_index((Window)dr) : -1;
        if (bi >= 0) { XGCValues gv;
            if (XGetGCValues(d, gc, GCForeground | GCBackground | GCLineWidth, &gv))
                rx_log("  RECT btn %d XDrawRect %ux%u@%d,%d fg=%lu bg=%lu lw=%d", bi, w, h, x, y, gv.foreground, gv.background, gv.line_width); } }
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawRectangle(d, dr, gc, x, y, w, h);
}
int XDrawLine(Display *d, Drawable dr, GC gc, int x1, int y1, int x2, int y2)
{
    REAL(XDrawLine);
    if (!rx_in_my_draw) rx_ld("XDrawLine", d, dr, 0, 0, x1, y1);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawLine(d, dr, gc, x1, y1, x2, y2);
}
int XDrawPoint(Display *d, Drawable dr, GC gc, int x, int y)
{
    REAL(XDrawPoint);
    if (!rx_in_my_draw) rx_ld("XDrawPoint", d, dr, 0, 0, x, y);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawPoint(d, dr, gc, x, y);
}
int XDrawPoints(Display *d, Drawable dr, GC gc, XPoint *p, int n, int mode)
{
    REAL(XDrawPoints);
    if (!rx_in_my_draw) rx_ld("XDrawPoints", d, dr, 0, 0, n > 0 ? p[0].x : 0, n > 0 ? p[0].y : 0);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawPoints(d, dr, gc, p, n, mode);
}
int XDrawArc(Display *d, Drawable dr, GC gc, int x, int y, unsigned int w, unsigned int h, int a1, int a2)
{
    REAL(XDrawArc);
    if (!rx_in_my_draw) rx_ld("XDrawArc", d, dr, 0, 0, x, y);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawArc(d, dr, gc, x, y, w, h, a1, a2);
}
int XFillArc(Display *d, Drawable dr, GC gc, int x, int y, unsigned int w, unsigned int h, int a1, int a2)
{
    REAL(XFillArc);
    if (!rx_in_my_draw) rx_ld("XFillArc", d, dr, 0, 0, x, y);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XFillArc(d, dr, gc, x, y, w, h, a1, a2);
}
/* Bulk/plural variants - Motif's shadow drawing (XmeDrawShadows) uses
 * XFillRectangles, which is what makes the armed arrow flash on click. */
int XFillRectangles(Display *d, Drawable dr, GC gc, XRectangle *rs, int n)
{
    REAL(XFillRectangles);
    /* Focus/location-cursor detection: Motif draws the ring as a 4-strip frame in
     * XmNhighlightColor (thin strips at the window edges).  Same frame in the bg
     * color = erase.  We flag it per render-cycle so losing focus (a redraw with
     * no such ring) clears it.  Still DROP the draw - we render our own dotted ring. */
    if (!rx_in_my_draw && rx_drawbtn) {
        int bi = rx_btn_index((Window)dr);
        int gadget = 0;
        if (bi < 0 && n > 0) { bi = rx_gadget_at((Window)dr, rs[0].x, rs[0].y); gadget = (bi >= 0); }
        if (bi >= 0 && n == 4) {
            struct rx_btn_s *b = &rx_btns[bi];
            XGCValues gv;
            if (!b->have_hl) {   /* resolve this button's highlight color once */
                unsigned long hl = 0;
                XtVaGetValues(b->w, "highlightColor", &hl, (char *)0);
                b->hlcolor = hl; b->have_hl = 1;
            }
            if (XGetGCValues(d, gc, GCForeground, &gv) && gv.foreground == b->hlcolor)
                b->focus_seen = 1;               /* this cycle has the ring */
            b->dirty = 1; rx_btn_schedule(b->w); /* re-render on any frame -> focus-loss clears too */
        }
        if (gadget) return 0;                    /* drop gadget shadow/frame */
    }
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XFillRectangles(d, dr, gc, rs, n);
}
int XDrawRectangles(Display *d, Drawable dr, GC gc, XRectangle *rs, int n)
{
    REAL(XDrawRectangles);
    if (!rx_in_my_draw && n>0) rx_listlog("DrawRects", d, dr, gc, rs[0].x, rs[0].y, rs[0].width, rs[0].height, 0, 0);
    if (!rx_in_my_draw && rx_verbose) { int bi = rx_drawbtn ? rx_btn_index((Window)dr) : -1;
        if (bi >= 0) { XGCValues gv;
            if (XGetGCValues(d, gc, GCForeground | GCBackground, &gv))
                rx_log("  RECT btn %d XDrawRects n=%d fg=%lu bg=%lu [0]=%ux%u@%d,%d", bi, n, gv.foreground, gv.background,
                    n > 0 ? rs[0].width : 0, n > 0 ? rs[0].height : 0, n > 0 ? rs[0].x : 0, n > 0 ? rs[0].y : 0); } }
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawRectangles(d, dr, gc, rs, n);
}
int XFillArcs(Display *d, Drawable dr, GC gc, XArc *a, int n)
{
    REAL(XFillArcs);
    if (!rx_in_my_draw) rx_ld("XFillArcs", d, dr, 0, 0, n > 0 ? a[0].x : 0, n > 0 ? a[0].y : 0);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XFillArcs(d, dr, gc, a, n);
}
int XDrawArcs(Display *d, Drawable dr, GC gc, XArc *a, int n)
{
    REAL(XDrawArcs);
    if (!rx_in_my_draw) rx_ld("XDrawArcs", d, dr, 0, 0, n > 0 ? a[0].x : 0, n > 0 ? a[0].y : 0);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XDrawArcs(d, dr, gc, a, n);
}
int XCopyPlane(Display *d, Drawable src, Drawable dst, GC gc, int sx, int sy,
               unsigned int w, unsigned int h, int dx, int dy, unsigned long plane)
{
    int bi;
    REAL(XCopyPlane);
    if (!rx_in_my_draw) {
        rx_ld("XCopyPlane", d, dst, 0, 0, dx, dy);
        bi = rx_drawbtn ? rx_btn_index(dst) : -1;
        if (bi >= 0) { rx_btn_blit(bi, RX_OP_COPYPLANE, src, gc, sx, sy, w, h, dx, dy, plane); return 0; }
        if (rx_draw && rx_is_sb_drawable(dst)) return 0;
    }
    return real_XCopyPlane(d, src, dst, gc, sx, sy, w, h, dx, dy, plane);
}
int XPutImage(Display *d, Drawable dr, GC gc, XImage *img, int sx, int sy,
              int dx, int dy, unsigned int w, unsigned int h)
{
    REAL(XPutImage);
    if (!rx_in_my_draw) rx_ld("XPutImage", d, dr, 0, 0, dx, dy);
    if (rx_is_owned_drawable(dr)) return 0;
    return real_XPutImage(d, dr, gc, img, sx, sy, dx, dy, w, h);
}
/* Piggyback Motif's geometry lookups into our size cache; drop on destroy - so
 * we never do our own (deadlock-prone) XGetGeometry from the render path. */
Status XGetGeometry(Display *d, Drawable dr, Window *root, int *x, int *y,
                    unsigned int *w, unsigned int *h, unsigned int *bw, unsigned int *depth)
{
    Status st;
    REAL(XGetGeometry);
    st = real_XGetGeometry(d, dr, root, x, y, w, h, bw, depth);
    if (st) rx_geom_set((Window)dr, *w, *h);
    return st;
}
int XDestroyWindow(Display *d, Window win)
{
    REAL(XDestroyWindow);
    rx_geom_del(win);
    return real_XDestroyWindow(d, win);
}

/* Record the metrics of Motif's actual label font so we can size the button to it. */
static void rx_set_font_gc(Display *d, int gi, GC gc)
{
    XGCValues gv; XFontStruct *fs;
    if (gi < 0) return;
    if (!XGetGCValues(d, gc, GCFont, &gv) || !gv.font) return;
    fs = XQueryFont(d, gv.font);
    if (fs) {
        if (fs->ascent + fs->descent > 0) {
            rx_btns[gi].font_asc = fs->ascent;
            rx_btns[gi].font_h   = fs->ascent + fs->descent;
        }
        XFreeFontInfo(NULL, fs, 1);
    }
}
static void rx_set_font_set(int gi, XFontSet fset)
{
    XFontSetExtents *ex;
    if (gi < 0 || !fset) return;
    ex = XExtentsOfFontSet(fset);
    if (ex && ex->max_logical_extent.height > 0) {
        rx_btns[gi].font_asc = -ex->max_logical_extent.y;
        rx_btns[gi].font_h   = ex->max_logical_extent.height;
    }
}

/* A label draw on a gadget's parent window at (x,y): capture the bytes for that
 * gadget in gadget-relative coords, so the render centers/places them correctly. */
static int rx_try_gadget_text(Window dr, GC gc, const char *s, int len, int x, int y)
{
    int gi, cx, cy, cw, ch;
    if (!rx_drawbtn) return -1;
    gi = rx_gadget_at(dr, x, y);
    if (gi < 0) return -1;
    /* Motif's clip on the label-draw GC == the gadget's EXACT bounds - use it as the
     * render rect so we never draw larger than the real button (no resize overspill). */
    { int got = rx_clip_get(gc, &cx, &cy, &cw, &ch);
      if (rx_verbose) rx_log("GADGET g%d clip=%d rect=%d,%d %dx%d  draw@%d,%d", gi, got, cx, cy, cw, ch, x, y);
      if (got && cw > 2 && ch > 2) {
          rx_btns[gi].grx = cx; rx_btns[gi].gry = cy; rx_btns[gi].grw = cw; rx_btns[gi].grh = ch;
      } }
    rx_btn_text(gi, s, len, x, y);       /* ABSOLUTE pwin coords */
    return gi;
}

/* Text draws: for a button window (or a gadget's parent), capture the label bytes
 * and suppress Motif's (we re-render them with Cairo); for a scrollbar, suppress. */
int XDrawString(Display *d, Drawable dr, GC gc, int x, int y, const char *s, int len)
{
    int bi;
    REAL(XDrawString);
    if (rx_in_my_draw) return real_XDrawString(d, dr, gc, x, y, s, len);
    rx_ld("XDrawString", d, dr, s, len, x, y);
    rx_listlog("DrawStr", d, dr, gc, x, y, 0, 0, s, len);
    bi = rx_drawbtn ? rx_btn_index(dr) : -1;
    if (bi >= 0) { rx_set_font_gc(d, bi, gc); rx_btn_text(bi, s, len, x, y); return 0; }
    { int gi = rx_try_gadget_text((Window)dr, gc, s, len, x, y); if (gi >= 0) { rx_set_font_gc(d, gi, gc); return 0; } }
    if (rx_draw && rx_is_sb_drawable(dr)) return 0;
    return real_XDrawString(d, dr, gc, x, y, s, len);
}
int XDrawImageString(Display *d, Drawable dr, GC gc, int x, int y, const char *s, int len)
{
    int bi;
    REAL(XDrawImageString);
    if (rx_in_my_draw) return real_XDrawImageString(d, dr, gc, x, y, s, len);
    rx_ld("XDrawImgStr", d, dr, s, len, x, y);
    rx_listlog("DrawImgStr", d, dr, gc, x, y, 0, 0, s, len);
    bi = rx_drawbtn ? rx_btn_index(dr) : -1;
    if (bi >= 0) { rx_set_font_gc(d, bi, gc); rx_btn_text(bi, s, len, x, y); return 0; }
    { int gi = rx_try_gadget_text((Window)dr, gc, s, len, x, y); if (gi >= 0) { rx_set_font_gc(d, gi, gc); return 0; } }
    if (rx_draw && rx_is_sb_drawable(dr)) return 0;
    return real_XDrawImageString(d, dr, gc, x, y, s, len);
}
void XmbDrawString(Display *d, Drawable dr, XFontSet fset, GC gc, int x, int y, const char *s, int len)
{
    int bi;
    REAL(XmbDrawString);
    if (!rx_in_my_draw) {
        rx_ld("XmbDrawStr", d, dr, s, len, x, y);
        rx_listlog("XmbStr", d, dr, gc, x, y, 0, 0, s, len);
        bi = rx_drawbtn ? rx_btn_index(dr) : -1;
        if (bi >= 0) { rx_set_font_set(bi, fset); rx_btn_text(bi, s, len, x, y); return; }
        { int gi = rx_try_gadget_text((Window)dr, gc, s, len, x, y); if (gi >= 0) { rx_set_font_set(gi, fset); return; } }
        if (rx_draw && rx_is_sb_drawable(dr)) return;
    }
    real_XmbDrawString(d, dr, fset, gc, x, y, s, len);
}
void XmbDrawImageString(Display *d, Drawable dr, XFontSet fset, GC gc, int x, int y, const char *s, int len)
{
    int bi;
    REAL(XmbDrawImageString);
    if (!rx_in_my_draw) {
        rx_ld("XmbDrawImg", d, dr, s, len, x, y);
        bi = rx_drawbtn ? rx_btn_index(dr) : -1;
        if (bi >= 0) { rx_set_font_set(bi, fset); rx_btn_text(bi, s, len, x, y); return; }
        { int gi = rx_try_gadget_text((Window)dr, gc, s, len, x, y); if (gi >= 0) { rx_set_font_set(gi, fset); return; } }
        if (rx_draw && rx_is_sb_drawable(dr)) return;
    }
    real_XmbDrawImageString(d, dr, fset, gc, x, y, s, len);
}

static void rx_sb_cb(Widget w, XtPointer a, XtPointer b)
{
    (void)a; (void)b;
    rx_draw_scrollbar(w);
}

/* Redraw on the events Motif would have used: last Expose, resize, map. */
static void rx_sb_evh(Widget w, XtPointer cd, XEvent *ev, Boolean *cont)
{
    (void)cd; (void)cont;
    if (ev->type == ConfigureNotify)
        rx_geom_set(ev->xconfigure.window, ev->xconfigure.width, ev->xconfigure.height);
    if (ev->type == Expose && ev->xexpose.count > 0) return;
    rx_draw_scrollbar(w);
}

static void rx_sb_destroy(Widget w, XtPointer a, XtPointer b)
{
    int i; (void)a; (void)b;
    for (i = 0; i < rx_nsb; i++)
        if (rx_sbwidgets[i] == w) rx_sbwidgets[i] = 0;
}

/* Register a scrollbar for custom drawing: remember its widget (so we can drop
 * Motif's paints to its window), hide Motif's arrows, and drive our redraw from
 * expose/resize and every value-change route. */
static void rx_hook_scrollbar(Widget w)
{
    static const char *const cbs[] = {
        "valueChangedCallback", "dragCallback", "incrementCallback",
        "decrementCallback", "pageIncrementCallback", "pageDecrementCallback",
        "toTopCallback", "toBottomCallback", 0
    };
    int i, slot = -1;
    if (!rx_draw) return;
    for (i = 0; i < rx_nsb; i++) if (!rx_sbwidgets[i]) { slot = i; break; }
    if (slot < 0 && rx_nsb < (int)(sizeof rx_sbwidgets / sizeof rx_sbwidgets[0]))
        slot = rx_nsb++;
    if (slot >= 0) rx_sbwidgets[slot] = w;

    XtAddEventHandler(w, ExposureMask | StructureNotifyMask, False, rx_sb_evh, (XtPointer)0);
    XtAddCallback(w, "destroyCallback", rx_sb_destroy, (XtPointer)0);
    for (i = 0; cbs[i]; i++)
        XtAddCallback(w, (char *)cbs[i], rx_sb_cb, (XtPointer)0);
}

/* --------------------------------------------------------- widget inventory
 * The document's vertical scrollbar is WP's own "scrollbar0" (inside "form1",
 * sibling to puparrow/pdownarrow).  The Motif "VertScrollBar"/"HorScrollBar"
 * instances are the auto-created children of the toolbar/property-bar
 * XmScrolledWindows - NOT the document - so we key on the name, and keep the
 * tallest vertical scrollbar as a fallback in case that name ever changes. */

static Widget    rx_docsb;              /* "scrollbar0" - document vscroll       */
static Widget    rx_docshell;           /* top-level shell that owns the document */
static Widget    rx_tallsb;            /* fallback: tallest vertical scrollbar   */
static Dimension rx_tallh;
static int       rx_menu_depth;         /* >0 while a Motif menu is posted (grab) */

static void rx_note_widget(Widget w)
{
    const char *cls  = rx_class(w);
    const char *name = XtName(w) ? XtName(w) : "(unnamed)";

    if (rx_verbose)
        rx_log("manage  class=%-18s name=%s", cls, name);

    rx_restyle(w, cls);

    /* Menu items: custom flat render (crisp font + hover + submenu/checkbox marks). */
    if (rx_in_menu(w)) {
        if (strcmp(cls, "XmCascadeButton") == 0)
            rx_hook_menuitem(w, RX_MENU_CASCADE);
        else if (strcmp(cls, "XmCascadeButtonGadget") == 0)
            rx_hook_menu_gadget(w, RX_MENU_CASCADE);   /* windowless submenu item */
        else if (strcmp(cls, "XmToggleButton") == 0)
            rx_hook_menuitem(w, RX_MENU_TOGGLE);
        else if (strcmp(cls, "XmToggleButtonGadget") == 0)
            rx_hook_menu_gadget(w, RX_MENU_TOGGLE);
        else if (strcmp(cls, "XmPushButton") == 0)
            rx_hook_menuitem(w, RX_MENU_NORMAL);
        else if (strcmp(cls, "XmPushButtonGadget") == 0)
            rx_hook_menu_gadget(w, RX_MENU_NORMAL);
        return;                                       /* handled */
    }

    if (strcmp(cls, "XmScrollBar") == 0) {
        Dimension h = 0, wd = 0;
        XtVaGetValues(w, "height", &h, "width", &wd, (char *)0);
        if (strcmp(name, "scrollbar0") == 0) {
            rx_docsb = w;
            rx_docshell = rx_shell(w);
            rx_log("captured document vscroll '%s' (%ux%u)", name, wd, h);
        } else if (h > wd && h > rx_tallh) {       /* vertical + tallest so far */
            rx_tallsb = w;
            rx_tallh  = h;
        }
        rx_hook_scrollbar(w);                       /* custom Cairo rendering */
    }
    else if (strcmp(cls, "XmArrowButton") == 0) {   /* spin arrows - use the real direction */
        unsigned char dir = 1;                       /* XmARROW_UP=0, XmARROW_DOWN=1 */
        XtVaGetValues(w, "arrowDirection", &dir, (char *)0);
        rx_hook_button(w, dir == 0 ? RX_KIND_UP : RX_KIND_DOWN);
    }
    else if (strcmp(cls, "XmPushButton") == 0) {    /* text button, or combo arrow */
        rx_hook_button(w, strcmp(name, "arrow") == 0 ? RX_KIND_DOWN : RX_KIND_TEXT);
    }
    else if (strcmp(cls, "XmPushButtonGadget") == 0) {  /* windowless dialog button */
        rx_hook_gadget(w, RX_KIND_TEXT);
    }
    else if (strcmp(cls, "XmCascadeButtonGadget") == 0) {  /* option-menu picker (gadget) */
        int i; rx_hook_gadget(w, RX_KIND_TEXT);
        for (i = 0; i < rx_nbtn; i++) if (rx_btns[i].w == w) { rx_btns[i].is_optbtn = 1; break; }
    }
    else if (strcmp(cls, "XmDrawnButton") == 0 && strcmp(name, "arrow") == 0) {
        rx_hook_button(w, RX_KIND_DOWN);
    }
    else if (strcmp(cls, "XmCascadeButton") == 0) {   /* menu-BAR item (File/Edit/...) - flat, no chevron */
        rx_hook_menuitem(w, RX_MENU_NORMAL);
    }
    else if (strcmp(cls, "XmToggleButton") == 0) {    /* dialog checkbox / radio */
        rx_hook_toggle(w);
    }
    else if (strcmp(cls, "XmLabel") == 0) {           /* dialog label - crisp, non-bold */
        rx_hook_label(w);
    }
    else if (strcmp(cls, "XmFrame") == 0) {           /* group box border */
        rx_hook_frame(w);
    }
    else if (strcmp(cls, "XiCombinationBox") == 0) {  /* WP combo/picker - modern rounded border */
        rx_hook_frame(w);
    }
    else if (strcmp(cls, "XmList") == 0) {            /* observe only, for now */
        rx_list_widget = w;
        if (rx_verbose) rx_log("observe XmList '%s'", XtName(w) ? XtName(w) : "");
    }
}

/* ------------------------------------------------------------- interposers */

/* Both XtCreateManagedWidget and XtVaCreateManagedWidget funnel through
 * XtManageChild / XtManageChildren, so hooking these two catches every managed
 * widget and gadget regardless of how it was created - no varargs to forward. */

void XtManageChild(Widget w)
{
    REAL(XtManageChild);
    rx_note_widget(w);
    real_XtManageChild(w);
}

void XtManageChildren(WidgetList children, Cardinal num)
{
    Cardinal i;
    REAL(XtManageChildren);
    for (i = 0; i < num; i++) rx_note_widget(children[i]);
    real_XtManageChildren(children, num);
}

/* Motif ABI (no motif-dev headers here): the XmScrollBarCallbackStruct layout
 * and the value-changed reason code are stable across OSF/Motif versions. */
typedef struct { int reason; XEvent *event; int value; int pixel; } RxSbCB;
#define RX_CR_VALUE_CHANGED 2
#define RX_CR_INCREMENT     3
#define RX_CR_DECREMENT     4
#define RX_CB_HAS_SOME      2            /* XtCallbackHasSome */

/* One wheel notch: nudge the document scrollbar and fire WP's own value-changed
 * callback so the page actually scrolls.  (Motif's XtSetValues moves the thumb
 * but does NOT invoke callbacks, so we invoke it ourselves - exactly what a
 * thumb-drag or arrow-release would do.)  Returns 1 if we handled it. */
/* Which scrollbar this wheel notch should drive, walking up from the widget
 * under the pointer, in priority order:
 *   1. a scrollbar directly under the pointer - HORIZONTAL or vertical - so the
 *      wheel scrolls a horizontal scrollbar you are hovering, not just a list;
 *   2. the vertical scrollbar of an enclosing XmScrolledWindow (pointer over an
 *      open drop list / scrolled content area);
 *   3. the document scrollbar (WP's text area is a plain XmDrawingArea, so it
 *      matches neither of the above). */
static Widget rx_wheel_target(XEvent *ev)
{
    Widget p, sw = 0;
    for (p = XtWindowToWidget(ev->xbutton.display, ev->xbutton.window); p; p = XtParent(p)) {
        const char *c = rx_class(p);
        if (strcmp(c, "XmScrollBar") == 0)
            return p;                                   /* hovering a scrollbar - drive it */
        if (!sw && strcmp(c, "XmScrolledWindow") == 0)
            XtVaGetValues(p, "verticalScrollBar", &sw, (char *)0);
        if (rx_is_shell(p)) {                           /* reached this widget's own window */
            if (sw) return sw;
            /* Fall back to the document scrollbar ONLY when the pointer is in the
             * document's own shell - a menu/dialog popup has its own shell here
             * (XmMenuShell / XmDialogShell), so it no longer scrolls the doc. */
            if (p == rx_docshell)
                return rx_docsb ? rx_docsb : rx_tallsb;
            return 0;
        }
    }
    if (sw) return sw;
    return 0;
}

static int rx_do_wheel(Widget sb, int dir /* -1 up, +1 down */, XEvent *ev)
{
    int val = 0, mn = 0, mx = 0, slider = 0, inc = 0, hi, nv;
    const char *stepcb = dir > 0 ? "incrementCallback" : "decrementCallback";
    int stepreason = dir > 0 ? RX_CR_INCREMENT : RX_CR_DECREMENT;
    RxSbCB cb;

    if (!sb) return 0;

    XtVaGetValues(sb, "value", &val, "minimum", &mn, "maximum", &mx,
                      "sliderSize", &slider, "increment", &inc, (char *)0);
    if (inc <= 0) inc = 1;
    hi = mx - slider;
    cb.event = ev;
    cb.pixel = 0;

    /* Some scrollbars (WP's font-name / point-size drop lists) scroll their
     * content from the arrow's increment/decrement callback, NOT valueChanged -
     * setting the value alone moves the thumb but not the view.  So if the arrow
     * callback exists, emulate <rx_wheel_lines> arrow clicks (exactly what the
     * working down-arrow does).  Otherwise fall back to value + valueChanged,
     * which is what the document / plain scrolled windows use. */
    if (XtHasCallbacks(sb, (char *)stepcb) == RX_CB_HAS_SOME) {
        int i;
        for (i = 0; i < rx_wheel_lines; i++) {
            nv = val + dir * inc;
            if (nv > hi) nv = hi;
            if (nv < mn) nv = mn;
            if (nv == val) break;
            val = nv;
            XtVaSetValues(sb, "value", val, (char *)0);
            cb.reason = stepreason;
            cb.value  = val;
            XtCallCallbacks(sb, (char *)stepcb, (XtPointer)&cb);
        }
        if (rx_verbose) rx_log("wheel(step) dir=%+d -> value %d", dir, val);
        return 1;
    }

    nv = val + dir * rx_wheel_lines * inc;
    if (nv > hi) nv = hi;
    if (nv < mn) nv = mn;
    if (nv == val) return 1;
    XtVaSetValues(sb, "value", nv, (char *)0);
    cb.reason = RX_CR_VALUE_CHANGED;
    cb.value  = nv;
    XtCallCallbacks(sb, "valueChangedCallback", (XtPointer)&cb);
    if (rx_verbose) rx_log("wheel(vc) dir=%+d  value %d -> %d", dir, val, nv);
    return 1;
}

/* THE event funnel: every X event WP handles passes here.  Buttons 4/5 are the
 * vertical wheel; WP binds nothing to them.  We drive the right scrollbar on the
 * press and swallow BOTH the press and the release - the release must not reach
 * WP, or an open combo drop list treats the wheel click as "dismiss". */
Boolean XtDispatchEvent(XEvent *ev)
{
    REAL(XtDispatchEvent);
    if (ev && (ev->type == ButtonPress || ev->type == ButtonRelease)) {
        unsigned int b = ev->xbutton.button;
        /* While a Motif menu is posted it holds a modal server/pointer grab;
         * driving a scrollbar's callback then (repaint + X round-trips) deadlocks
         * the whole app.  So leave the wheel entirely to WP while a menu is up. */
        if ((b == 4 || b == 5) && rx_menu_depth == 0) {
            Widget target = rx_wheel_target(ev);
            if (target) {
                if (ev->type == ButtonPress)
                    rx_do_wheel(target, b == 5 ? +1 : -1, ev);
                return 1;                /* swallow press AND release             */
            }
            /* nothing to scroll -> let WP have the event */
        }
    }
    return real_XtDispatchEvent(ev);
}

void XtRealizeWidget(Widget w)
{
    REAL(XtRealizeWidget);
    if (rx_verbose)
        rx_log("realize class=%-18s name=%s", rx_class(w), XtName(w) ? XtName(w) : "(unnamed)");
    real_XtRealizeWidget(w);
}

/* Track a posted Motif menu's modal grab so the wheel stands down while one is
 * up (driving a scrollbar during that grab deadlocks the app).  Every spring-
 * loaded menu adds an Xt modal grab when posted and removes it when dismissed -
 * a far more reliable signal than XtPopup, which Motif doesn't route menus
 * through.  Keyed on XmMenuShell so combo drop lists (a different shell) still
 * scroll. */
void XtAddGrab(Widget w, Boolean exclusive, Boolean spring_loaded)
{
    REAL(XtAddGrab);
    if (rx_in_menu(w)) {
        rx_menu_depth++;
        if (rx_skin) rx_restyle_tree(rx_shell(w));   /* reskin the menu as it posts */
        if (rx_verbose) rx_log("menu grab+  depth=%d", rx_menu_depth);
    }
    real_XtAddGrab(w, exclusive, spring_loaded);
}

void XtRemoveGrab(Widget w)
{
    REAL(XtRemoveGrab);
    if (rx_in_menu(w) && rx_menu_depth > 0) {
        rx_menu_depth--;
        if (rx_verbose) rx_log("menu grab-  depth=%d", rx_menu_depth);
        if (rx_menu_depth == 0) {   /* menu fully closed: drop any stuck highlight */
            int i;
            for (i = 0; i < rx_nbtn; i++)
                if (rx_btns[i].w && rx_btns[i].is_menu && (rx_btns[i].hovered || rx_btns[i].armed)) {
                    rx_btns[i].hovered = 0; rx_btns[i].armed = 0;
                    rx_btns[i].dirty = 1; rx_btn_schedule(rx_btns[i].w);
                }
        }
    }
    real_XtRemoveGrab(w);
}
