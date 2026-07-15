# WP 8.1 — internal Xlib/Xt helpers retroXt calls (not interposed)

retroXt calls ~38 Xlib/Xt functions it does *not* reskin (render helpers, widget
introspection, callbacks). Three ways to reach xwp's Xlib for these, decided by
where each function keeps its state.

## Key fact (the "swap the library" insight)
xwp's statically-linked Xlib is **XFree86 3.3.x** — proven by exact byte matches
(e.g. XtManageChild). The extracted `libX11.so.6.1` / `libXt.so.6.0` are the *same
build*, so their **Display / widget / GC struct layouts are identical** to xwp's.
That means a *second* same-ABI Xlib instance linked into retroXt81 operates
correctly on xwp's `Display*` — exactly why 8.0's shared dynamic lib works. My
earlier "must map everything" was over-cautious: it's only true against a *modern*
(different-layout) libX11.

## Decision table

### (A) Xlib helpers → just call the linked 3.3.5 libX11. NO mapping needed.
All Xlib per-connection state lives *in the Display struct* (output buffer,
sequence, resource-id allocator) with identical 3.3.5 layout, so a second instance
is consistent: `XCreateGC XFreeGC XCreatePixmap XFreePixmap XCopyGC XGetGCValues
XSetForeground XCreateImage XDestroyImage XQueryFont XQueryColor XAllocColor
XQueryTree XGetWindowAttributes XTranslateCoordinates XFlush XFree XSetErrorHandler
XExtentsOfFontSet XFreeFontInfo`.
Caveat: don't free a pointer across allocators — always pair
XCreateImage/XDestroyImage, XGetImage/XFree, etc. (already true in retroXt).

### (B) Pure Xt accessors → linked libXt is fine (they only read the widget struct).
`XtParent XtWindow XtName XtClass XtIsRealized XtIsManaged XtIsSensitive
XtDisplayOfObject XtHasCallbacks XtTranslateCoords`. The widget struct is shared
and same-layout, so reading it from either instance is correct.

### (C) Process-global Xt → MUST use xwp's own libXt instance.
libXt keeps a **process-global per-display registry** (window→widget table, per-
display app-context data) *outside* any shared struct. A second libXt instance has
its own empty registry, so these would fail: `XtWindowToWidget`
`XtWidgetToApplicationContext` `XtAppAddTimeOut` `XtAddCallback`
`XtAddEventHandler` `XtCallCallbacks` `XtVaGetValues` `XtVaSetValues`.
These need to route into xwp's static libXt (detour trampoline / direct address),
OR retroXt must avoid them (e.g. keep its own widget-registry, drive the flush
timer through a source we control). Best confirmed on the live process (gdb).

## Statically mapped so far (for the pure-map path, or as gdb start points)

Opcode-verified (X11 request opcode stored at req[0]):
```
XCreateGC              0x08678030   op55
XFreeGC                0x0867a060   op60
XCreatePixmap          0x08678710   op53
XFreePixmap            0x0867a0f0   op54
XQueryTree             0x08683270   op15
XGetWindowAttributes   0x0867b2f0   op3
XTranslateCoordinates  0x08687a40   op40
XQueryColor            0x08682f00   op91
XAllocColor            0x0867aa50   op84
```
Exact body match (sim 1.00):
```
XFree                  0x0868b0e0
XDestroyImage          0x0867ef60
```
Tiny widget-field accessor (exact `mov eax,[ebp+8]; mov eax,[eax+OFF]; ret`):
```
XtWindow               0x0865c110   [w+0x60]   (unique)
XtParent               0x0865c220   [w+0x08]   (unique in Xt cluster)
```

Not statically resolvable with confidence (near-identical tiny accessors / PIC
globals turned absolute): the rest of (B) and all of (C) — verify on live xwp with
`verify.gdb` (break at a candidate, check the arg widget / return value).

## Recommendation
Link the 3.3.5 `libX11`/`libXt` into retroXt81 → (A)+(B) need no mapping at all.
Only the ~8 group-(C) functions need routing to xwp's libXt; pin those with gdb on
the running app rather than by disassembly guesswork.
