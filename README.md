# WordPerfect 8 for Linux — modern-glibc revival

Run **Corel® WordPerfect® 8 for Linux** (1998) — a 32-bit, statically-`libc5`
application — on a present-day glibc / X11 system, with **no recompilation of
the original binaries**. This repository contains two independent pieces of
original work:

- **`retro5/`** — a **libc5 → glibc compatibility shim** (`retro5.so`). It
  reimplements the parts of the 1996-era Linux `libc.so.5` ABI that modern
  glibc changed (stdio `FILE` layout, `struct stat`, `errno`, directory
  reading, startup) and forwards everything else. The original binaries are
  *retargeted in place* — a handful of same-length byte edits swap
  `libc.so.5 → retro5.so`, `libm.so.5 → libm.so.6`, and the ELF interpreter
  `ld-linux.so.1 → ld-linux.so.2`; nothing in the binary moves. Although it was
  built for WordPerfect, the shim is generic and can retarget **any** old
  libc5 ELF32 program.

- **`installer/`** — a zero-to-installed installer (GTK wizard + CLI) that lays
  down a working WordPerfect 8 tree from **your own** original Corel media,
  builds and installs the shim, applies the runtime fixes, and creates
  launchers / menu entries.

## ⚠️ What this repository does *not* contain

This project ships **none of Corel's software**. To use it you must supply your
own legally-obtained copy of the WordPerfect 8 for Linux media. Specifically,
**not** included here (and never to be committed — see `.gitignore`):

- WordPerfect program binaries, `.drs`/`.lrs` resources, fonts, or any other
  Corel media files;
- any decompiled or disassembled output derived from those binaries;
- reverse-engineering data (string tables, call graphs, symbol databases)
  extracted from the copyrighted binaries;
- any registration-key generator.

`docs/registration-key-scheme.md` describes, for historical/technical purposes,
how the installer's registration check worked; it is documentation, not a
key generator, and it does not remove your obligation to hold a valid license.

## Requirements

- A 32-bit-capable Linux system (`i386` multiarch libraries).
- `gcc` with `-m32` support, `binutils`, `python3`, and (for the GUI installer)
  GTK 4 / PyGObject.
- Your original Corel WordPerfect 8 for Linux media.

## Quick start

Build the shim:

```sh
cd retro5
make            # produces retro5.so (32-bit)
```

Install WordPerfect from your media (CLI):

```sh
python3 installer/wp8_install.py --target ~/.local/share/wordperfect8 --media /path/to/wp8-media
```

…or run the GTK wizard:

```sh
python3 installer/wp8_installer.py
```

See `installer/README.md` for the full installer story (system-wide install,
uninstall, single-instance / document opening) and `retro5/README.md` for how
the shim works.

## Repository layout

```
retro5/       libc5 -> glibc shim + retargeting tools
installer/    WordPerfect 8 installer (GTK wizard + CLI engine)
tools/        wpdecom2.c — decompressor for Corel's \xffWPC LZSS format
docs/         technical notes (incl. the registration-key scheme)
```

## Legal / trademark

WordPerfect and Corel are trademarks of their respective owners. This is an
independent, unaffiliated interoperability and preservation project; it is not
sponsored, endorsed by, or associated with Corel. "WordPerfect" is used only
descriptively, to identify the software this tooling interoperates with.

All original code in this repository is licensed under the MIT License
(`LICENSE`).
