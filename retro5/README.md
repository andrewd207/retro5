# retro5 — a libc5 → glibc shim for 1990s Linux binaries

`retro5.so` lets a 32-bit ELF program that was linked against the ancient Linux
`libc.so.5` (roughly 1995–1998) run on a modern glibc system unchanged. It was
written to revive Corel WordPerfect 8 for Linux, but nothing in it is
WordPerfect-specific — it is a general libc5 compatibility layer.

## Why a shim is needed

libc5 and glibc (`libc.so.6`) are **not** ABI-compatible. The soname bump from
`.5` to `.6` is precisely the signal that the ABI changed. The differences that
actually bite old binaries:

- **`FILE` layout.** libc5 programs frequently inline `getc`/`putc`, reading
  fields directly out of the `FILE` struct at fixed offsets. glibc's `FILE`
  has a different layout, so you cannot hand a glibc `FILE*` to code that
  expects a libc5 one. `retro5` therefore **reimplements** buffered stdio with
  the libc5 `FILE` layout (`src/stdio5.c`), rather than forwarding it.
- **`struct stat`.** Field offsets and integer widths differ; `retro5`
  translates (`src/os5.c`, `xlate_stat`).
- **Directory reading.** libc5 `struct dirent` differs from glibc's; `readdir`
  is reimplemented on top of `getdents64`.
- **`errno`.** libc5 exposes a plain global `errno`; glibc uses a
  thread-local accessed via `__errno_location()`. The shim keeps both in sync
  **bidirectionally** so the common `errno = 0; op(); if (errno) …` idiom in
  old code works. (Getting this wrong caused a spurious "File IO Error" — the
  fix was to copy the shim's `errno` *into* glibc's before each forwarded call,
  not only after.)
- **Startup / misc.** `__libc_init`, FPU control word, `setjmp`/`longjmp`
  (`src/setjmp5.S`), copy-relocated data symbols (`src/data5.c`).

Everything else (~200+ symbols) is a thin forward to the real glibc function
via `dlsym(RTLD_NEXT, …)` — see `src/forward.c`.

## How the retargeting works

Rather than `LD_PRELOAD` at runtime, the binaries are edited once. `patchelf`
can't be used: growing `.dynstr` corrupts the ancient `.hash` table and the
loader `SIGFPE`s on `nbuckets == 0`. Instead we do **same-length in-place byte
edits** — nothing in the file moves, `.hash` stays intact:

```
interpreter  /lib/ld-linux.so.1  ->  /lib/ld-linux.so.2
DT_NEEDED    libc.so.5           ->  retro5.so         (both 9 bytes)
DT_NEEDED    libm.so.5           ->  libm.so.6
.dynsym      errno               ->  STV_HIDDEN
```

`retro5.so` is deliberately 9 characters — exactly `len("libc.so.5")` — so the
`DT_NEEDED` string can be overwritten in place.

## Tools

| script | purpose |
|--------|---------|
| `Makefile`             | `make` builds `retro5.so` (32-bit); `make check` reports still-missing libc symbols; `make patch` retargets a copy of a target binary |
| `retarget.sh`          | batch-retarget ELF32+libc5 binaries in place (`--scan <dir>` walks a tree) |
| `hidesym.py`           | mark a `.dynsym` symbol `STV_HIDDEN` (same-length edit) |
| `apply-patches.sh`     | byte-guarded runtime bug fixes for the WordPerfect binaries |
| `collect-imports.sh`   | union of all undefined libc symbols across a tree (what the shim must provide) |
| `detect-static-x11.sh` | flag binaries that statically embed ancient X11 transport code |
| `build-tree.sh`        | decompress + retarget a whole WordPerfect suite into a root |

## Requirements

`retro5.so` is a **32-bit (i386)** shared object, so you need a 32-bit
toolchain and 32-bit runtime libraries even on an x86-64 host.

**Build** (Debian/Ubuntu package names):

| need | package |
|------|---------|
| 32-bit gcc / libc headers | `gcc-multilib` (pulls `libc6-dev-i386`) |
| linker / `readelf` / `objcopy` | `binutils` |
| `make` | `make` |

```sh
sudo apt install gcc-multilib binutils make
```

Fedora/RHEL equivalents: `glibc-devel.i686`, `libgcc.i686`, `binutils`, `make`.

**Runtime** (to actually *run* retargeted binaries): the 32-bit loader and the
libraries the binaries still link by their modern sonames —

```sh
sudo dpkg --add-architecture i386 && sudo apt update
sudo apt install libc6:i386 libm6:i386        # (libm is part of libc6)
# for X11/Motif apps such as WordPerfect:
sudo apt install libx11-6:i386 libxt6:i386 libxpm4:i386 libxext6:i386
```

## Build & install

```sh
make                     # -> retro5.so (32-bit); prints SONAME + export count
sudo make install        # -> /usr/lib/i386-linux-gnu/retro5.so + ldconfig
```

`make install` drops the shim in a directory the 32-bit loader searches by
**default**, so retargeted binaries find it with **no `LD_LIBRARY_PATH`**. One
copy serves every retargeted program on the system. Overridables:

```sh
sudo make install LIBDIR=/some/other/libdir   # non-multiarch layout
make install DESTDIR=/tmp/stage               # staged/packaged build (no ldconfig effect)
sudo make uninstall                           # remove it again
```

For a throwaway or unprivileged setup you can skip `make install` and instead
put `retro5.so` on `LD_LIBRARY_PATH` yourself, but the installed path is the
clean way.
