# wpprint-sink — a modern WordPerfect 8 print subsystem

A clean-room reimplementation of WordPerfect 8 for Linux's print helpers. It
speaks WP's own text protocol (see
[`../docs/print-ipc-protocol.md`](../docs/print-ipc-protocol.md)) and drives a
modern spooler — CUPS `lp`/`lpr` — instead of the 1998 SysV `lp`/`qprt` path and
the `.all` printer-driver database.

**Why:** WP talks to `xwpdest`/`wpexc`/`xwppmgr` over a UNIX socket / FIFO using
a small newline-terminated token protocol (`e_wpexc1` handshake,
`e_job`/`e_form`/`e_device`/`e_go`/`e_print`/`e_done`, …). The native helpers run
under the retro5 shim and already exec CUPS `lp`/`lpr`, so this is **Plan B** —
for when the ancient helpers misbehave, and to give a fully modern print path
(and a live protocol probe).

## Build & test

```sh
make            # -> ./wpsink ./wpselect
make test       # unit tests + the sink self-test
```

## Components

| file | role | replaces |
|---|---|---|
| `wpproto.{h,c}` | RE'd protocol constants + line I/O + spool | (shared) |
| `wpexec.{h,c}` | `wpexc`-faithful runner: pipe/fork/exec, stdout capture | `wpexc` core |
| `wpdest.{h,c}` | WP device/form/orientation → CUPS `lp` command | `xwpdest` cmd build |
| `wpcups.{h,c}` | enumerate CUPS destinations (via `lpstat`) | WP `.all` driver DB |
| `wpsink.c` | the sink: WP protocol → spool job to CUPS | `xwpdest`/`wpexc` job path |
| `wpselect.c` | pick which CUPS printer WP targets; write a sidecar the sink reads | WP "Select/Add Printer" logic |
| `wpprinter-dialog.py` | GTK4 "Select/Add Printer" dialog (lists CUPS queues, calls `wpselect`) | WP's X11 printer-select UI |

## Division of labour (what we build vs what CUPS already does)

WP's own dialogs (Print / Select Printer / Printer Create-Edit / Printer Setup)
reimplement a whole printer-administration stack — driver list, add/delete,
per-printer Sheet Feeder (trays), Initial Font, Destination, Cartridges/Fonts,
`/etc/printcap` editing. **On a modern system that's CUPS's job, and the dialogs
already exist** (`system-config-printer`, GNOME Settings ▸ Printers, the CUPS web
admin). So we do **not** rebuild them:

| WP concept | modern owner |
|---|---|
| add / delete / configure a printer | CUPS + the system printer tool (we launch it) |
| per-printer paper size / tray / media-type / quality **defaults** | CUPS printer config; applied automatically on `lp -d NAME` |
| which printer WP prints to | **us** (`wpselect` / the dialog) |
| per-*job* copies / page-range / quality / color | WP's own Print dialog → IPC → our `wpdest` → `lp -o …` |

Our dialog therefore just picks the CUPS destination and shows that printer's
current defaults read-only (via `wpselect --info`); "Configure Printers…" opens
the system tool. `wpdest` still *can* emit `-o InputSlot/MediaType/…` for per-job
overrides WP passes, but normally CUPS defaults cover them.

## Printer model (the key design decision)

**One PostScript `.prs`, N CUPS destinations — we do NOT mint a `.prs` per
printer.** WP's "Passthru PostScript" `.prs` already describes generic PostScript
capabilities (paper sizes, PS fonts) — enough to lay out any document. A CUPS
printer is a **destination**, not a capability set, so "select/add printer" just
chooses which CUPS queue the passthru command targets (`lp -d NAME`), recorded in
a sidecar (`$WPCOM/wpsink.dest`) the sink adopts. Synthesizing WP's `.prs`
capability format per printer is thereby avoided entirely.

```
wpselect --set NAME  ─writes─▶  $WPCOM/wpsink.dest
WP ──IPC──▶ wpsink ──reads sidecar──▶  lp -d NAME  ──▶ CUPS ──▶ printer
```

## Use

```sh
./wpselect --list                     # list CUPS printers + default
./wpselect --set CLX-3160             # make it WP's print destination
./wpsink   --fifo /tmp/wpc-XXXX -v    # spool WP jobs to that printer via lp -d
./wpsink   --socket PATH --spool lpr  # or an explicit spool command
```

## Install as an option (drop-in)

The modern print system is opt-in and reversible. `install.sh` swaps WP's
`xwpdest` for a drop-in (`xwpdest-dropin.sh`, original kept as `xwpdest.orig`):

```sh
sudo ./install.sh /path/to/wp            # WP's Print > Select… now opens our dialog
sudo ./install.sh --uninstall /path/to/wp   # restore stock xwpdest
```

The drop-in intercepts **only** the interactive printer-select call
(`… .set … _wq` with a DISPLAY) and opens the CUPS dialog; the job/spool path and
any unrecognised invocation **fall through to the original `xwpdest`**, so
printing is never broken by enabling this. (This will become a checkbox in the
main installer.)

## Modality & Wayland

WP's real `xwpdest` is a **modal, transient-to-WP** dialog — it imports
`XSetTransientForHint`, `XReparentWindow`, `XGrab{Keyboard,Pointer}`, and uses
Motif `dialog_*_modal`, parenting to WP's `CLIENT_WINDOW`. Our dialog matches
this: the drop-in launches it with **`GDK_BACKEND=x11`** so it's an XWayland
client on the **same X server as WP** (a native Wayland client can't parent
across to another app — so we deliberately don't be one), and the dialog calls
`XSetTransientForHint` via `ctypes`→`libX11` against WP's window id, plus GTK
`set_modal`. The exact way WP hands over its `CLIENT_WINDOW` id (argv vs the
selection socket) is confirmed by `capture-print-traffic.sh`; until then the
drop-in passes `$WINDOWID` and the dialog still works (just non-transient) if
absent.

## Status

- done: protocol vocabulary + transport, message loop, handshake, spool-to-CUPS
- done: `wpexec` runner, `wpdest` mapper, `wpcups` enumeration, `wpselect` — all
  unit-tested (`make test`); live CUPS enumeration + full `wpselect → wpsink →
  lp -d` loop demonstrated
- todo: **exact wire framing** of the job body (inline text vs the 4-byte-LE
  framed mode) and the `e_device`/`e_form` payload — settle empirically with
  [`capture-print-traffic.sh`](capture-print-traffic.sh) (spots marked
  `<< CONFIRM (trace) >>`)
- todo: the exact `$WPCOM/wpc-*` socket suffix WP binds (auto-attach)
- todo: **X11 "Select/Add Printer" dialog** wrapping `wpselect`+`wpcups`, and the
  **selection-side IPC** telling xwp the printer changed (likely `e_device`;
  confirm from capture)

MIT licensed. Ships no WordPerfect/Corel code.
