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
# mor_read_entry @0x08230c74 does strcpy(deadbuf, PTR_s_about_087b71c0[byte&0x7f]).
# The particle table has only 43 entries (idx 0..0x2a); a dictionary byte >0x2a
# indexes past it into a text buffer -> strcpy of a bogus pointer -> SIGSEGV as
# you type. The dst buffer is write-only dead code, so we NOP the 5-byte
# `call strcpy` at 0x08230dda. file off = 0x3210+(0x08230dda-0x0804b210)=0x1e8dda.
patch_bytes wpbin/xwp 1e8dda e82997e1ff 9090909090 \
    "xwp: NOP dead OOB strcpy in mor_read_entry (typing crash)"

echo "== done =="
