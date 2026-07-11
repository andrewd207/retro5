/* wp81_detours.h  -- WP 8.1 xwp statically-linked Xt/X11 functions to inline-detour.
 * X(name, addr, steal_bytes)  steal = whole instr boundary >= 5 (jmp rel32).
 *
 * Addresses are byte-exact (reloc-masked) against the AUTHORITATIVE reference
 * XFree86 3.3.2 libX11.a/libXt.a (gcc 2.7.2.3) -- xwp's own build.  This corrected
 * five addresses the earlier BSim/opcode map got wrong:
 *   XtManageChildren   0x0865db60 -> 0x0865df30  (0865db60 is really XtUnmanageChildren)
 *   XtRealizeWidget    0x08667ea0 -> 0x0865bac0
 *   XSetClipRectangles 0x086857a0 -> 0x08685940
 *   XSetClipMask       0x08685940 -> 0x08685990  (old addr was XSetClipRectangles)
 *   XPutImage          0x086829b0 -> 0x08682c70  (0x086829b0 is really PutImageRequest,
 *                                                 the internal that writes the X_PutImage opcode)
 * Re-validate with scratchpad/gen_forward.py against the 3.3.2 libs. */

#ifndef WP81_DETOURS_H
#define WP81_DETOURS_H

#define WP81_DETOUR_LIST(X) \
    X(XtDispatchEvent           , 0x08657ab0, 6) \
    X(XtAddGrab                 , 0x08657d00, 6) \
    X(XtRemoveGrab              , 0x08657da0, 5) \
    X(XtManageChildren          , 0x0865df30, 6) \
    X(XtManageChild             , 0x0865e040, 5) \
    X(XtRealizeWidget           , 0x0865bac0, 7) \
    X(XSetWindowBackground      , 0x086763f0, 5) \
    X(XClearWindow              , 0x08676f60, 5) \
    X(XClearArea                , 0x08676fd0, 5) \
    X(XCopyArea                 , 0x08677cc0, 5) \
    X(XCopyPlane                , 0x08677d60, 5) \
    X(XDestroyWindow            , 0x08678960, 5) \
    X(XDrawArc                  , 0x086789f0, 5) \
    X(XDrawLine                 , 0x08678a90, 6) \
    X(XDrawLines                , 0x08678b80, 6) \
    X(XDrawPoint                , 0x08678cd0, 6) \
    X(XDrawPoints               , 0x08678db0, 6) \
    X(XDrawRectangle            , 0x08679050, 6) \
    X(XDrawSegments             , 0x08679140, 6) \
    X(XFillArc                  , 0x08679370, 6) \
    X(XFillPolygon              , 0x08679460, 6) \
    X(XFillRectangle            , 0x086795c0, 6) \
    X(XFillRectangles           , 0x086796a0, 6) \
    X(XGetGeometry              , 0x0867a980, 6) \
    X(XDrawImageString          , 0x0867cbf0, 9) \
    X(XSetWindowBackgroundPixmap, 0x08680c20, 5) \
    X(XPutImage                 , 0x08682c70, 6) \
    X(XSetClipRectangles        , 0x08685940, 5) \
    X(XSetClipMask              , 0x08685990, 7) \
    X(XDrawString               , 0x08686930, 6) \
    X(XTextExtents              , 0x08686ce0, 6) \
    X(XTextWidth                , 0x08686f50, 6)

#define WP81_NDETOUR 32

/* per-name absolute address + steal length */
#define WP81_ADDR_XtDispatchEvent            0x08657ab0
#define WP81_STEAL_XtDispatchEvent           6
#define WP81_ADDR_XtAddGrab                  0x08657d00
#define WP81_STEAL_XtAddGrab                 6
#define WP81_ADDR_XtRemoveGrab               0x08657da0
#define WP81_STEAL_XtRemoveGrab              5
#define WP81_ADDR_XtManageChildren           0x0865df30
#define WP81_STEAL_XtManageChildren          6
#define WP81_ADDR_XtManageChild              0x0865e040
#define WP81_STEAL_XtManageChild             5
#define WP81_ADDR_XtRealizeWidget            0x0865bac0
#define WP81_STEAL_XtRealizeWidget           7
#define WP81_ADDR_XSetWindowBackground       0x086763f0
#define WP81_STEAL_XSetWindowBackground      5
#define WP81_ADDR_XClearWindow               0x08676f60
#define WP81_STEAL_XClearWindow              5
#define WP81_ADDR_XClearArea                 0x08676fd0
#define WP81_STEAL_XClearArea                5
#define WP81_ADDR_XCopyArea                  0x08677cc0
#define WP81_STEAL_XCopyArea                 5
#define WP81_ADDR_XCopyPlane                 0x08677d60
#define WP81_STEAL_XCopyPlane                5
#define WP81_ADDR_XDestroyWindow             0x08678960
#define WP81_STEAL_XDestroyWindow            5
#define WP81_ADDR_XDrawArc                   0x086789f0
#define WP81_STEAL_XDrawArc                  5
#define WP81_ADDR_XDrawLine                  0x08678a90
#define WP81_STEAL_XDrawLine                 6
#define WP81_ADDR_XDrawLines                 0x08678b80
#define WP81_STEAL_XDrawLines                6
#define WP81_ADDR_XDrawPoint                 0x08678cd0
#define WP81_STEAL_XDrawPoint                6
#define WP81_ADDR_XDrawPoints                0x08678db0
#define WP81_STEAL_XDrawPoints               6
#define WP81_ADDR_XDrawRectangle             0x08679050
#define WP81_STEAL_XDrawRectangle            6
#define WP81_ADDR_XDrawSegments              0x08679140
#define WP81_STEAL_XDrawSegments             6
#define WP81_ADDR_XFillArc                   0x08679370
#define WP81_STEAL_XFillArc                  6
#define WP81_ADDR_XFillPolygon               0x08679460
#define WP81_STEAL_XFillPolygon              6
#define WP81_ADDR_XFillRectangle             0x086795c0
#define WP81_STEAL_XFillRectangle            6
#define WP81_ADDR_XFillRectangles            0x086796a0
#define WP81_STEAL_XFillRectangles           6
#define WP81_ADDR_XGetGeometry               0x0867a980
#define WP81_STEAL_XGetGeometry              6
#define WP81_ADDR_XDrawImageString           0x0867cbf0
#define WP81_STEAL_XDrawImageString          9
#define WP81_ADDR_XSetWindowBackgroundPixmap 0x08680c20
#define WP81_STEAL_XSetWindowBackgroundPixmap 5
#define WP81_ADDR_XPutImage                  0x08682c70
#define WP81_STEAL_XPutImage                 6
#define WP81_ADDR_XSetClipRectangles         0x08685940
#define WP81_STEAL_XSetClipRectangles        5
#define WP81_ADDR_XSetClipMask               0x08685990
#define WP81_STEAL_XSetClipMask              7
#define WP81_ADDR_XDrawString                0x08686930
#define WP81_STEAL_XDrawString               6
#define WP81_ADDR_XTextExtents               0x08686ce0
#define WP81_STEAL_XTextExtents              6
#define WP81_ADDR_XTextWidth                 0x08686f50
#define WP81_STEAL_XTextWidth                6

#endif
