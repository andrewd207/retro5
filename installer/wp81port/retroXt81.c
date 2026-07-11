/* retroXt81.c -- WP 8.1 build variant of the retroXt Motif skinner.
 *
 * WP 8.1's `xwp` links Xt/X11/Motif STATICALLY, so the hooks can't be reached by
 * LD_PRELOAD symbol interposition the way they are on 8.0.  Instead we compile
 * the EXACT SAME hook bodies from ../retroXt.c and reach them via inline detours
 * over the functions' fixed absolute addresses (see wp81port/wp81_xt_symbols.map).
 *
 * Everything is in ../retroXt.c under `#ifdef RX_STATIC81`:
 *   - REAL(name) resolves to the detour trampoline orig_<name> (not dlsym)
 *   - a constructor installs the detours (rx_install_detours81) via detour81.c
 * so this file is just the build entry point -- one source of truth, 8.0 and 8.1
 * never drift.
 *
 * Build (from the installer/ directory so the "wp81port/..." includes resolve):
 *   gcc -m32 -shared -fPIC -fvisibility=hidden -O2 -DRX_STATIC81 \
 *       -I/usr/include/cairo -o wp81port/retroXt81.so \
 *       wp81port/retroXt81.c wp81port/detour81.c \
 *       -Wl,--no-as-needed -l:libXt.so.6 -l:libX11.so.6 -ldl
 * (-fvisibility=hidden keeps the XFillRectangle/... hook symbols out of the
 *  dynamic table so they neither interpose nor collide with the libX11 this .so
 *  links for its own rendering calls.)
 *
 * Run (dev):  RETROXT_LOG=/tmp/rx81.log LD_PRELOAD=$PWD/wp81port/retroXt81.so <8.1 launcher>
 */
#define RX_STATIC81 1
#include "../retroXt.c"
