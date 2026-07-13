# printertocups — WordPerfect 8's print backend, on CUPS

A small **32-bit** shared library that replaces the interface WordPerfect 8 uses to talk to its
1998 print server (`xwpdest`/`wpexc` over a fragile startup-IPC FIFO). CUPS is the real print
server, so jobs go straight to it via **libcups**.

- **`dlopen`'d, not linked** — `retro5.so` deep-loads this (`RTLD_DEEPBIND`) only when printing is
  enabled, and this library in turn deep-loads `libcups.so.2`, so CUPS's modern glibc/gnutls deps
  never collide with WP's libc5 shim (the same isolation cairo/librsvg use).
- **Async + thread-safe** — `p2c_submit()` copies the job body + options and returns immediately; a
  worker thread does the (potentially slow) CUPS submission off WP's UI thread. One worker serializes
  submissions, so libcups' per-thread HTTP state is trivially safe; the job queue is the only shared
  state and is fully mutex/condvar-guarded.
- **No startup IPC race** — because the print interface is intercepted in-process and jobs are handed
  straight to CUPS, there is no external helper handshake to hang on.

## API (`p2c.h`)
```c
int  p2c_init(void);                      // dlopen libcups + start worker
int  p2c_enum(P2CPrinter *out, int max);  // list CUPS destinations
long p2c_submit(dest, title, format,      // queue a job (async); P2C_POSTSCRIPT / P2C_PDF
                data, len, opts, nopt);
int  p2c_wait_idle(int timeout_ms);       // drain (tests / shutdown)
void p2c_shutdown(void);
```

## Build & test
```sh
make                 # -> printertocups.so (32-bit) + p2c-test
./p2c-test list      # enumerate CUPS destinations (safe)
./p2c-test submit DEST FILE.ps   # spool a PostScript file (prints!)
```

## Status
- **done:** threaded thread-safe queue, libcups enumeration (verified against live CUPS), async
  submit via `cupsCreateJob`/`StartDocument`/`WriteRequestData`/`FinishDocument`, per-job IPP options.
- **gated:** the takeover is enabled by an env var (**`RETRO5_CUPS`**), defaulted in the
  `~/.local/bin/xwp-8.*` launchers so an end user can flip it.
- **todo (integration):** the retro5 hook that redirects WP's print path into `p2c_submit` — the
  intercepted WP functions/IPC live in the per-build `R5Syms` table (8.0/8.1 share the code). Needs
  the print-IPC interception points RE'd (which function WP calls to enqueue a job, and the job-body
  format).

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
