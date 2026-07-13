# printertocups — WordPerfect 8's print backend, on CUPS

A small **32-bit** shared library that makes CUPS WordPerfect 8's real print backend — for
**enumeration, capabilities, and submission**, not just spooling. CUPS is the real print server, so
jobs go straight to it via **libcups**.

WP 8's actual print path (live-verified, §18.8 of FONT-RENDERING-MAP.md) is *not* a socket protocol:
`xwp` forks `wpp`→`wppx`, which assembles an on-disk PostScript file and hands it to a shell spool
command (`lpr -P<dev> <file>`). Merely hijacking that command would send bytes to CUPS but leave WP
believing it drives a frozen Type1-PostScript `.prs`. Real integration means WP's printer **list**
comes from `cupsGetDests`, its **capabilities** (page sizes, resolutions, duplex, color, trays) come
from CUPS via IPP (`p2c_caps`), and the **job** goes to `cupsCreateJob`/libcups — the printer analog
of the font-system takeover.

- **`dlopen`'d, not linked** — `retro5.so` deep-loads this (`RTLD_DEEPBIND`) only when printing is
  enabled, and this library in turn deep-loads `libcups.so.2`, so CUPS's modern glibc/gnutls deps
  never collide with WP's libc5 shim (the same isolation cairo/librsvg use).
- **Async + thread-safe** — `p2c_submit()` copies the job body + options and returns immediately; a
  worker thread does the (potentially slow) CUPS submission off WP's UI thread. One worker serializes
  submissions, so libcups' per-thread HTTP state is trivially safe; the job queue is the only shared
  state and is fully mutex/condvar-guarded.
- **No legacy spool detour** — the print path is intercepted in-process and jobs go straight to CUPS,
  so there is no `wpp`/`wppx` fork or shell `lpr` handoff to spawn or hang on.

## API (`p2c.h`)
```c
int  p2c_init(void);                      // dlopen libcups + start worker
int  p2c_enum(P2CPrinter *out, int max);  // list CUPS destinations
int  p2c_caps(dest, P2CCaps *out);        // query a queue's caps via IPP (media/res/duplex/color/trays)
long p2c_submit(dest, title, format,      // queue a job (async); P2C_POSTSCRIPT / P2C_PDF
                data, len, opts, nopt);
int  p2c_wait_idle(int timeout_ms);       // drain (tests / shutdown)
void p2c_shutdown(void);
```

## Build & test
```sh
make                 # -> printertocups.so (32-bit) + p2c-test
./p2c-test list      # enumerate CUPS destinations (safe)
./p2c-test caps DEST # query a queue's capabilities via IPP (safe, read-only)
./p2c-test submit DEST FILE.ps   # spool a PostScript file (prints!)
```

## Status
- **done:** threaded thread-safe queue; libcups enumeration (`p2c_enum`) and capability query
  (`p2c_caps`, via the IPP dest-info API `cupsCopyDestInfo`/`cupsFindDest*`) — both verified against
  live CUPS 2.4; async submit via `cupsCreateJob`/`StartDocument`/`WriteRequestData`/`FinishDocument`,
  per-job IPP options.
- **gated:** the takeover is enabled by an env var (**`RETRO5_CUPS`**), defaulted in the
  `~/.local/bin/xwp-8.*` launchers so an end user can flip it.
- **todo (integration):** the retro5 hooks that back WP's printer subsystem with the three calls
  above — (1) enumeration → feed WP's printer list from `p2c_enum`; (2) **capabilities → populate
  WP's in-memory printer-capability model (the `.prs`-derived struct) from `p2c_caps`** so Page
  Setup / Print dialogs reflect the real queue; (3) submission → route the assembled job to
  `p2c_submit`. The WP-side structures + interception points live in the per-build `R5Syms` table
  (8.0/8.1 share the code) and are being mapped now (FONT-RENDERING-MAP.md §19 / `wp_printer_model.h`).

## PDF is the preferred target (not PostScript)

WP emits **PostScript** with its **Type1** fonts via the passthru `.prs`. But **PDF is a superset of
PostScript** and modern CUPS/printers embed fonts — especially **TrueType** — far better in PDF than
in that Type1 PostScript. So the intended path is **PS → PDF** (Ghostscript `pdfwrite`, or a native
cairo/FreeType render) with the fonts **embedded as TTF**, then submit `P2C_PDF`.

This closes the loop with the TTF font modernization: the same system TTFs we render on screen
(FreeType/cairo) should be the ones **embedded in the printed PDF**, instead of WP substituting a
Type1 face. Where WP's PS references a font by resource name, we remap/embed the real TTF at the
PS→PDF stage (a Ghostscript Fontmap, or by driving the render from our font model). `p2c_submit`
already accepts `P2C_PDF`; the converter/embedder is the remaining integration piece.

MIT licensed. Ships no WordPerfect/Corel code.
