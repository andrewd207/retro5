#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""check-symbols.py — report libc5 symbols that retro5.so does not yet provide.

Scan one or more directories/files for 32-bit ELF binaries in the libc5 world
(DT_NEEDED libc.so.5, or already retargeted to retro5.so), take the union of
their undefined symbols, and report which of those the shim does NOT export.
Run it after adding a new program or suite to confirm retro5.so covers it (and
to get the exact list of forwards to add to src/forward.c if it doesn't).

Deciding which undefined symbols the shim is *responsible* for:
  * With a reference libc.so.5 (--libc5 PATH, or auto-detected): the answer is
    exactly the undefined symbols that libc5 itself exports — precise. Corel's
    media even bundles one (wpbin/libc.so.5.4.46), which is auto-detected when a
    scanned tree contains it.
  * Without one: subtract retro5.so's exports plus the modern system libraries
    the binaries still link (libm/libX11/libXt/libXpm/...); whatever remains
    would fail to resolve — a superset, but still actionable.

Exit status: 0 if nothing is missing, 1 if any symbol is missing, 2 on setup error.

  ./check-symbols.py /path/to/wp8/tree
  ./check-symbols.py --shim build/retro5.so --libc5 /path/to/libc.so.5 bin1 bin2
"""
import argparse
import os
import re
import subprocess
import sys

LIBC5_PATHS = [
    "/usr/i386-compat-gnulibc1/lib/libc.so.5",
    "/usr/lib/i386-linux-gnulibc1/libc.so.5",
]
# modern sonames a retargeted binary still resolves against (not the shim's job)
SYSTEM_LIBS = [
    "/lib/i386-linux-gnu/libm.so.6", "/lib/i386-linux-gnu/libdl.so.2",
    "/lib/i386-linux-gnu/libX11.so.6", "/lib/i386-linux-gnu/libXt.so.6",
    "/lib/i386-linux-gnu/libXpm.so.4", "/lib/i386-linux-gnu/libXext.so.6",
    "/lib/i386-linux-gnu/libSM.so.6", "/lib/i386-linux-gnu/libICE.so.6",
    "/lib/i386-linux-gnu/libXmu.so.6",
]


def dynsyms(path, undef):
    """Set of dynamic symbol names; undef=True -> UND imports, else definitions."""
    out = set()
    r = subprocess.run(["readelf", "-sW", "--dyn-syms", path],
                       capture_output=True, text=True)
    for ln in r.stdout.splitlines():
        p = ln.split()
        if len(p) < 8 or not p[0].endswith(":"):
            continue
        if p[3] in ("FUNC", "OBJECT", "IFUNC"):
            name = p[7].split("@")[0]
            ndx = p[6]
            if name and ((undef and ndx == "UND") or (not undef and ndx != "UND")):
                out.add(name)
    return out


def is_elf32(p):
    try:
        with open(p, "rb") as f:
            h = f.read(5)
        return h[:4] == b"\x7fELF" and h[4] == 1
    except OSError:
        return False


def needed(p):
    r = subprocess.run(["readelf", "-dW", p], capture_output=True, text=True).stdout
    return re.findall(r"\[([^\]]+)\]",
                      "\n".join(l for l in r.splitlines() if "NEEDED" in l))


def find_shim(explicit):
    if explicit:
        return explicit
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "retro5.so"), os.path.join(here, "build/retro5.so")):
        if os.path.isfile(c):
            return c
    return None


def find_libc5(explicit, roots):
    if explicit:
        return explicit
    for root in roots:                       # bundled in a scanned tree?
        if os.path.isdir(root):
            for dp, _, fn in os.walk(root):
                for f in fn:
                    if re.match(r"libc\.so\.5", f):
                        return os.path.join(dp, f)
    for p in LIBC5_PATHS:                     # system compat lib?
        if os.path.isfile(p):
            return p
    return None


def main(argv):
    ap = argparse.ArgumentParser(description="report libc5 symbols retro5.so lacks")
    ap.add_argument("paths", nargs="+", help="dirs/files of libc5 ELF32 binaries")
    ap.add_argument("--shim", help="retro5.so (default: auto-detect next to this script)")
    ap.add_argument("--libc5", help="reference libc.so.5 for precise scoping "
                    "(default: auto-detect bundled or system compat lib)")
    a = ap.parse_args(argv)

    shim = find_shim(a.shim)
    if not shim or not os.path.isfile(shim):
        print("error: retro5.so not found; build it (make) or pass --shim",
              file=sys.stderr)
        return 2
    shim_exports = dynsyms(shim, False)

    files = []
    for p in a.paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for dp, _, fn in os.walk(p):
                files.extend(os.path.join(dp, f) for f in fn)
    bins = [f for f in files if is_elf32(f)
            and any(n in ("libc.so.5", "retro5.so") for n in needed(f))]
    if not bins:
        print("no libc5/retro5 ELF32 binaries found under:", *a.paths, file=sys.stderr)
        return 2
    need = set()
    for b in bins:
        need |= dynsyms(b, True)

    libc5 = find_libc5(a.libc5, a.paths)
    if libc5:
        need_from_shim = need & dynsyms(libc5, False)
        method = f"precise (vs {libc5})"
    else:
        sysexp = set()
        for lib in SYSTEM_LIBS:
            if os.path.isfile(lib):
                sysexp |= dynsyms(lib, False)
        need_from_shim = need - sysexp
        method = "approximate (no libc.so.5 reference; subtracted system libs)"

    missing = sorted(need_from_shim - shim_exports)
    print(f"scanned {len(bins)} libc5 ELF32 binaries; scope: {method}")
    print(f"shim exports: {len(shim_exports)}; "
          f"symbols needed from shim: {len(need_from_shim)}")
    if missing:
        print(f"\nMISSING from retro5.so ({len(missing)}) — add forwards to src/forward.c:")
        for m in missing:
            print("  ", m)
        return 1
    print("\nOK: retro5.so provides every needed libc5 symbol.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
