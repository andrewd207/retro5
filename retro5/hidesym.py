#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# hidesym.py <elf32> <sym> [<sym>...]
# Marks the named DEFINED .dynsym symbols STV_HIDDEN (st_other visibility = 2),
# so the dynamic linker won't let them satisfy other objects' references.
# Used to stop wpinstg's non-TLS `errno` from hijacking glibc's TLS `errno`
# (which makes ld.so SIGFPE allocating static TLS for the non-TLS main exe).
# Same-length in-place edit (one byte per symbol) — nothing moves.
import sys, struct

fn = sys.argv[1]
targets = set(sys.argv[2:])
d = bytearray(open(fn, 'rb').read())
assert d[:4] == b'\x7fELF' and d[4] == 1, "not a 32-bit ELF"

e_shoff    = struct.unpack_from('<I', d, 0x20)[0]
e_shentsz  = struct.unpack_from('<H', d, 0x2e)[0]
e_shnum    = struct.unpack_from('<H', d, 0x30)[0]
e_shstrndx = struct.unpack_from('<H', d, 0x32)[0]

def shdr(i):
    o = e_shoff + i * e_shentsz
    name, typ, flags, addr, off, size, link, info, align, entsz = \
        struct.unpack_from('<IIIIIIIIII', d, o)
    return dict(name=name, off=off, size=size)

shstr = shdr(e_shstrndx)
def secname(n):
    o = shstr['off'] + n
    return d[o:d.index(0, o)].decode()

dynsym = dynstr = None
for i in range(e_shnum):
    s = shdr(i); nm = secname(s['name'])
    if nm == '.dynsym': dynsym = s
    elif nm == '.dynstr': dynstr = s
assert dynsym and dynstr, "no .dynsym/.dynstr"

hidden = []
for i in range(dynsym['size'] // 16):
    o = dynsym['off'] + i * 16
    st_name  = struct.unpack_from('<I', d, o)[0]
    st_shndx = struct.unpack_from('<H', d, o + 14)[0]
    no = dynstr['off'] + st_name
    name = d[no:d.index(0, no)].decode()
    if name in targets and st_shndx != 0:      # defined
        d[o + 13] = (d[o + 13] & ~0x3) | 2      # visibility -> STV_HIDDEN
        hidden.append(name)

open(fn, 'wb').write(d)
print("hidden:", hidden if hidden else "(none matched)")
