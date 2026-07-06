#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""retarget.py — retarget a libc5 ELF32 binary to the modern glibc + retro5 world.

Self-contained (no other files needed). For each 32-bit ELF that links libc.so.5,
apply the SAME-LENGTH in-place edits — nothing moves, the ancient .hash stays
intact (patchelf grows .dynstr and corrupts it -> loader SIGFPE) — and hide the
non-TLS errno so glibc/libm bind their own thread-local errno instead:

    interpreter  /lib/ld-linux.so.1  ->  /lib/ld-linux.so.2
    DT_NEEDED    libc.so.5           ->  retro5.so         (both 9 bytes)
    DT_NEEDED    libm.so.5           ->  libm.so.6
    .dynsym      errno               ->  STV_HIDDEN

Then run it with retro5.so on the loader path, e.g.:
    LD_LIBRARY_PATH=/usr/lib/i386-linux-gnu ./the-binary
(or `make install` retro5.so into /usr/lib/i386-linux-gnu so no path is needed).

  ./retarget.py <file> [<file> ...]     retarget specific ELF32 files in place
  ./retarget.py --scan <dir>            find & retarget every ELF32+libc5 under dir
  ./retarget.py --backup <file>         keep a <file>.preretarget copy first

Idempotent: files already retargeted (no libc.so.5) are skipped. Read-only files
are handled (the mode is temporarily made writable and then restored).
"""
import os
import struct
import sys

REPLACEMENTS = [
    (b"/lib/ld-linux.so.1\x00", b"/lib/ld-linux.so.2\x00"),
    (b"libc.so.5\x00", b"retro5.so\x00"),
    (b"libm.so.5\x00", b"libm.so.6\x00"),
]


def is_elf32(data):
    return data[:4] == b"\x7fELF" and len(data) > 4 and data[4] == 1


def links_libc5(data):
    return b"libc.so.5\x00" in data


def hide_errno(data):
    """Mark the DEFINED .dynsym symbol 'errno' STV_HIDDEN (same-length edit) so a
    copy-relocated non-TLS errno can't hijack glibc's TLS errno. Returns bytearray."""
    d = bytearray(data)
    if not is_elf32(d):
        return d
    e_shoff = struct.unpack_from("<I", d, 0x20)[0]
    e_shentsz = struct.unpack_from("<H", d, 0x2e)[0]
    e_shnum = struct.unpack_from("<H", d, 0x30)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x32)[0]
    if not e_shoff or not e_shnum:
        return d

    def shdr(i):
        return struct.unpack_from("<IIIIIIIIII", d, e_shoff + i * e_shentsz)

    so_off = shdr(e_shstrndx)[4]

    def secname(n):
        o = so_off + n
        return d[o:d.index(0, o)].decode(errors="replace")

    dynsym = dynstr = None
    for i in range(e_shnum):
        nm = shdr(i)
        name = secname(nm[0])
        if name == ".dynsym":
            dynsym = nm
        elif name == ".dynstr":
            dynstr = nm
    if not dynsym or not dynstr:
        return d
    sym_off, sym_size = dynsym[4], dynsym[5]
    str_off = dynstr[4]
    for i in range(sym_size // 16):
        o = sym_off + i * 16
        st_name = struct.unpack_from("<I", d, o)[0]
        st_shndx = struct.unpack_from("<H", d, o + 14)[0]
        no = str_off + st_name
        name = d[no:d.index(0, no)].decode(errors="replace")
        if name == "errno" and st_shndx != 0:
            d[o + 13] = (d[o + 13] & ~0x3) | 2         # STV_HIDDEN
    return d


def retarget_file(path, backup=False):
    data = open(path, "rb").read()
    if not is_elf32(data):
        return "skip (not ELF32)"
    if not links_libc5(data):
        return "skip (already glibc / not libc5)"
    d = data
    for old, new in REPLACEMENTS:
        d = d.replace(old, new)
    d = bytes(hide_errno(d))
    if d == data:
        return "no change"
    if backup and not os.path.exists(path + ".preretarget"):
        with open(path + ".preretarget", "wb") as f:
            f.write(data)
    # handle read-only inputs (e.g. straight off a CD image)
    mode = os.stat(path).st_mode
    made_writable = False
    if not os.access(path, os.W_OK):
        os.chmod(path, mode | 0o200)
        made_writable = True
    try:
        with open(path, "wb") as f:
            f.write(d)
    finally:
        if made_writable:
            os.chmod(path, mode)
    return "retargeted"


def iter_targets(paths, scan):
    if scan:
        for base in paths:
            for dp, _, fn in os.walk(base):
                for f in fn:
                    yield os.path.join(dp, f)
    else:
        yield from paths


def main(argv):
    backup = False
    scan = False
    args = []
    for a in argv:
        if a == "--scan":
            scan = True
        elif a == "--backup":
            backup = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            args.append(a)
    if not args:
        print(__doc__)
        return 2

    n_ret = n_skip = 0
    for path in iter_targets(args, scan):
        try:
            r = retarget_file(path, backup=backup)
        except OSError as e:
            r = f"error ({e})"
        if r == "retargeted":
            n_ret += 1
            print(f"  retargeted: {path}")
        else:
            n_skip += 1
            if not scan:                    # quiet skips when walking a tree
                print(f"  {r}: {path}")
    print(f"== retargeted {n_ret}, skipped {n_skip} ==")
    return 0 if n_ret or not scan else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
