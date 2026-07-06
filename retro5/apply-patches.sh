#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# apply-patches.sh - same-length in-place byte patches applied to the installed
# WP8 tree AFTER build-tree.sh/retarget.sh. Re-run safe (verifies before/after).
#
#   ./apply-patches.sh [ROOT]     default ROOT=/usr/wplinux
set -u
ROOT=${1:-/usr/wplinux}

# patch <file> <hexoffset> <expect-hex> <new-hex> <desc>
patch_bytes() {
    local f="$ROOT/$1" off="$2" exp="$3" new="$4" desc="$5"
    [ -f "$f" ] || { echo "  MISS $1 ($desc)"; return; }
    python3 - "$f" "$off" "$exp" "$new" "$desc" <<'PY'
import sys
f,off,exp,new,desc=sys.argv[1:6]
off=int(off,16); exp=bytes.fromhex(exp); new=bytes.fromhex(new)
assert len(exp)==len(new), "patch must be same length"
b=bytearray(open(f,"rb").read())
cur=bytes(b[off:off+len(exp)])
if cur==new:
    print(f"  ok(already) {desc}")
elif cur==exp:
    b[off:off+len(new)]=new; open(f,"wb").write(b)
    print(f"  PATCHED {desc}")
else:
    print(f"  SKIP {desc}: bytes at 0x{off:x} = {cur.hex()} (expected {exp.hex()})")
PY
}

echo "== applying WP8 binary patches in $ROOT =="

# --- xwp: morphology decoder out-of-bounds strcpy (typing crash) ---------------
# mor_read_entry does strcpy(deadbuf, PARTICLE_TABLE[byte & 0x7f]). The table has
# only 43 entries (idx 0..0x2a); a dictionary byte >0x2a indexes past it into an
# adjacent text buffer -> strcpy of a bogus pointer -> SIGSEGV as you type. The
# dst buffer is write-only dead code, so we NOP the 5-byte `call strcpy`.
#
# WHY IT'S FATAL ON THE PORT BUT WAS LATENT ON 1998 libc5 (best-guess root cause):
# It's a data-dependent out-of-bounds *read*, not a write. table[idx] for idx>0x2a
# fetches 4 bytes from the buffer past the table and uses them as the strcpy SOURCE
# pointer; the crash we caught had src=0x64646464 = "dddd" (the user's keystrokes
# reinterpreted as an address). Whether strcpy faults depends only on whether that
# stray pointer is mapped:
#   - original static-libc5 (fixed Linux-2.0 layout, one malloc, no ASLR): the
#     adjacent slot dereferenced to readable memory, so the errant strcpy copied
#     garbage into a dead buffer and never faulted -> shipped latent for ~25 years;
#   - modern glibc + retro5: different heap/arena/mmap+ASLR + adjacent contents, so
#     the stray pointer lands on an unmapped page -> SIGSEGV while typing.
# Not a shim defect (the .mor fread is byte-identical to the file; index values are
# unchanged) — only the memory environment the stray pointer is read against changed,
# which is exactly what a libc5->glibc port changes. NOPing the dead call is neutral.
#
# Multiple builds carry the same bug at different offsets; each line is byte-guarded,
# so only the matching build is patched (the other lines SKIP harmlessly).
#   0x08230dda (8.16MB static-X build):  file off 0x1e8dda, call = e82997e1ff
#   0x08259cff (8.0.0076 dynamic-X build): file off 0x211cff, call = e8fc53dfff
patch_bytes wpbin/xwp 1e8dda e82997e1ff 9090909090 \
    "xwp: NOP dead OOB strcpy in mor_read_entry (8.16MB static build)"
patch_bytes wpbin/xwp 211cff e8fc53dfff 9090909090 \
    "xwp: NOP dead OOB strcpy in mor_read_entry (8.0.0076 dynamic build)"

echo "== done =="
