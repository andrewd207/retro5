# WP 8.1 static Xt/X11 function map

WP 8.1's `xwp` is a stripped, non-PIC `EXEC` with Xt/X11/Motif linked **statically**
(only `libm` + `retro5` are dynamic). To port the retroXt interposition to 8.1 we must
patch the prologues of the same functions retroXt overrides. This directory locates
every one of those functions inside `xwp`.

## How the addresses were found
Reference build: **XFree86 3.3.5** libc `.so`s pulled from the Corel Linux OS ISO
(`libXt.so.6.0`, `libX11.so.6.1`) — the exact X11 build WP 8.1's era linked. Methods:

- **op\<N\>**  — X11 request wrappers store their protocol opcode as `mov byte [req],N`
  (e.g. `X_CopyArea`=62). Ground-truth: opcode-bearing candidate in the drawing cluster.
- **+order**  — collisions (single vs. plural sharing an opcode) resolved by link order
  (static linker preserves `.a` member order; monotonic alignment against the reference).
- **changeattr-maskN** — `XSetWindowBackground`/`Pixmap` share `X_ChangeWindowAttributes`
  (op 2); disambiguated by the value-mask (`CWBackPixel`=2 vs `CWBackPixmap`=1) at req+8.
- **sig / wrapper-exact** — Xt funcs (no protocol opcode) matched by register-agnostic
  normalized signature; `XtManageChild` is the exact `XtManageChildren(&w,1)` wrapper.

**Not linked** (`XDrawArcs`, `XDrawRectangles`, `XFillArcs`, `XmbDrawString`,
`XmbDrawImageString`): batch/i18n variants live in separate `.o` members and WP/Motif
never calls them, so the linker omitted them — nothing to patch. (Confirmed: singular
draw funcs fill their whole slot; no 8-arg fontset-draw dispatcher exists in xwp.)

## Files
- `wp81_xt_symbols.map` — human-readable map (addr, size, lib, verification).
- `wp81_xt_symbols.nm`  — `nm` format (`ADDR T name`).
- `wp81_xsyms.s` / `.o` — gdb-loadable absolute symbols.
- `gen_syms.py`, `locate_op.py`, `final_map.py`, `match81.py` — the locator toolchain.

## The prologue patcher (inline-detour port)

Because `xwp` is non-PIC, every mapped function sits at a fixed absolute address, so
we don't need symbol interposition (impossible on 8.1 anyway) — we rewrite each
prologue in memory to `jmp hook` and keep a **trampoline** (relocated prologue + jump
back) so hooks can still call the original.

- `detour81.h` / `detour81.c` — the engine. `detour_install(tab, n)` installs
  `{name, target, hook, orig, steal}` entries: builds the trampoline into a static
  RWX arena, `mprotect`s the code page, writes a 5-byte `E9` rel32 jump, nops the
  rest of the stolen prologue. Memory ops use raw `int 0x80` (GOT-safe under PIC) to
  avoid binding to retro5's libc5 `mprotect`/`mmap` in the flat namespace.
- `wp81_detours.h` — **generated** (`make regen` / `patch81.py`). `steal` = whole
  instruction boundary ≥5 bytes; patch81.py has proven with capstone that every
  stolen region is relocation-safe (no relative branch, not an internal jump target).
  Steal lengths: 5–9 bytes.
- `retroXt81.c` — the port shim: `#define RX_STATIC81` + `#include "../retroXt.c"`.
  It compiles the **exact same hook bodies** as the 8.0 build; under `RX_STATIC81`
  retroXt.c reroutes its `REAL(name)` macro (and the 3 inline commit-path `dlsym`
  sites) to the `orig_<name>` detour trampolines instead of `dlsym(RTLD_NEXT)`, and
  its constructor calls `rx_install_detours81()` to patch the prologues. One source
  of truth — 8.0 and 8.1 never drift. Built `-fvisibility=hidden` so the hook
  symbols stay out of the dynamic table (they'd otherwise collide with the libX11
  this `.so` links for its own rendering calls).

### Runtime status / remaining blocker
The wiring compiles clean in both modes and the detour mechanics are proven, but
**it is not yet runnable on live 8.1**: retroXt's own rendering helpers call Xlib/Xt
functions it does *not* interpose (`XCreatePixmap`, `XCreateGC`, `XGetGCValues`,
`XtParent`, …). On 8.0 those share xwp's single dynamic libX11. On 8.1 they'd bind
to the *system* libX11 this `.so` links, which would operate on xwp's ancient
(X11R6.3, static) `Display*` with a mismatched struct layout → corruption. Fix:
map those ~15–20 extra Xlib/Xt functions in xwp (same opcode/order/reference method
that produced wp81_xt_symbols.map) and route retroXt's internal calls through their
trampolines too, so *all* X traffic goes through xwp's own static Xlib. Then link no
external libX11 at all.

```
make            # builds retroXt81.so + detour_selftest
make test       # ./detour_selftest -> "SELFTEST PASS" (hook fires, orig preserved)
RETROXT81_LOG=1 LD_PRELOAD=$PWD/retroXt81.so <wp8.1 launcher>
```

Verified: the engine self-test passes (PIC and non-PIC), and a cross-module test
(preloaded `.so` constructor detouring a function in a non-PIC exe — the exact xwp
shape) redirects the callee's normal `call` while preserving the original.

Injection: `LD_PRELOAD` loads the shim and runs its constructor even though the
target is statically linked (we patch machine code, not symbols). The persistent
install is the `DT_NEEDED` rewrite noted in the interposer memory.

## Using in gdb
Against the unmodified binary:
```
add-symbol-file wp81_xsyms.o 0      # break XtManageChild / info address … work
```
For reverse lookup + disassembly labels, build an annotated copy (regenerated, ~8 MB):
```
TV=0x804b210   # xwp .text vaddr
objcopy $(awk '{printf "--add-symbol %s=.text:0x%x,function,global ",$3,strtonum("0x"$1)-TV}' wp81_xt_symbols.nm) \
        ~/.local/share/wordperfect/8.1/wpbin/xwp wp81_xwp.symbols
gdb wp81_xwp.symbols   # info symbol ADDR, break, <name> labels in disasm
```
