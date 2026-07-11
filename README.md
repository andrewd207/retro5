# retro5 — run 1990s libc5 Linux binaries on a modern glibc system

`retro5.so` is a **libc5 → glibc compatibility shim**. It lets a 32-bit ELF
program that was linked against the ancient Linux `libc.so.5` (roughly
1995–1998) run unchanged on a present-day glibc system — **no recompilation,
no source**. The original binaries are *retargeted in place*: a handful of
same-length byte edits swap `libc.so.5 → retro5.so`, `libm.so.5 → libm.so.6`,
and the ELF interpreter `ld-linux.so.1 → ld-linux.so.2`; nothing in the binary
moves, so even the fragile ancient `.hash` table stays intact.

The shim reimplements the parts of the libc5 ABI that glibc changed — the
`FILE` layout (old code inlines `getc`/`putc` and reads `FILE` fields
directly), `struct stat`, directory reading, `errno` (libc5's plain global vs
glibc's thread-local), and process startup — and forwards everything else
(~200+ symbols) straight to glibc via `dlsym(RTLD_NEXT, …)`.

See **`retro5/README.md`** for how it works in detail.

## Flagship use case: Corel WordPerfect 8 for Linux (and the whole suite)

retro5 was built to revive **Corel® WordPerfect® 8 for Linux** (1998), a
statically-`libc5` X11/Motif application, on modern Linux — and it does: the
real editor runs, renders, and takes input on a 2020s X server. Because the
shim and its `retarget.sh --scan` are entirely binary-agnostic, the *same*
approach revives the rest of the **Corel Linux office suite** shipped in the
same era — every libc5 ELF32 in the tree can be retargeted in one pass.

The **`installer/`** directory contains a zero-to-installed installer (GTK
wizard + CLI) that lays down a working WordPerfect 8 tree from **your own**
original Corel media, builds and installs the shim, applies the runtime fixes,
and creates launchers / menu entries.

## ⚠️ What this repository does *not* contain

This project ships **none of Corel's software.** To install WordPerfect you must
supply your own legally-obtained copy of the media. Never included here (and
blocked by `.gitignore`):

- WordPerfect / suite program binaries, `.drs`/`.lrs` resources, fonts, or any
  other Corel media files;
- any decompiled or disassembled output derived from those binaries;
- reverse-engineering data (string tables, call graphs, symbol databases)
  extracted from the copyrighted binaries;
- any registration-key generator.

`docs/registration-key-scheme.md` describes, for historical/technical purposes,
how the installer's registration check worked; it is documentation, not a key
generator, and it does not remove your obligation to hold a valid license.

## Requirements

- A 32-bit-capable Linux system (`i386` multiarch libraries: `libc6:i386`,
  `libx11-6:i386`, `libxt6:i386`, `libxpm4:i386`).
- `gcc` with `-m32` support, `binutils`, `python3`, and (for the GUI installer)
  GTK 4 / PyGObject.

## Quick start

Build the shim:

```sh
cd retro5
make            # produces retro5.so (32-bit)
```

Retarget any old libc5 binary to run on glibc:

```sh
./retro5/retarget.sh /path/to/some/libc5/program      # in-place, reversible from a backup
```

Install WordPerfect 8 from your media (CLI):

```sh
python3 installer/wp8_install.py --target ~/.local/share/wordperfect8 --media /path/to/wp8.iso
```

…or run the GTK wizard:

```sh
python3 installer/wp8_install_gui.py
```

## Repository layout

```
retro5/       the libc5 -> glibc shim + retargeting tools  (the core of this repo)
installer/    Corel WordPerfect 8 installer (GTK wizard + CLI engine)
tools/        retarget.py (retarget any libc5 ELF32 -> retro5, self-contained),
              wpdecom2.c (Corel \xffWPC LZSS decompressor),
              verify-regnum.py (verify-only registration-number checker)
docs/         technical notes (incl. the registration-key scheme)
```

## Legal / trademark

WordPerfect and Corel are trademarks of their respective owners. This is an
independent, unaffiliated interoperability and preservation project; it is not
sponsored, endorsed by, or associated with Corel. Product names are used only
descriptively, to identify the software this tooling interoperates with.

All original code in this repository is licensed under the MIT License
(`LICENSE`).
