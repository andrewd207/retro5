#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# retarget.sh - batch-retarget libc5 ELF32 binaries to the glibc world.
#
# For every 32-bit ELF that links libc.so.5, apply the same-length in-place
# edits (nothing moves, .hash intact) and hide the non-TLS errno:
#   interpreter  /lib/ld-linux.so.1 -> /lib/ld-linux.so.2
#   DT_NEEDED    libc.so.5          -> retro5.so
#   DT_NEEDED    libm.so.5          -> libm.so.6
#   .dynsym      errno              -> STV_HIDDEN
#
#   ./retarget.sh <file> [<file>...]     patch specific ELF32 files (in place)
#   ./retarget.sh --scan <dir>           find & patch every ELF32+libc5 under dir
#
# Idempotent: files already retargeted (no libc.so.5) are skipped.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
HIDESYM="$HERE/hidesym.py"
n_patched=0 n_skipped=0

is_elf32() { file -b "$1" 2>/dev/null | grep -q '^ELF 32-bit'; }
links_libc5() { readelf -d "$1" 2>/dev/null | grep -q 'libc\.so\.5'; }

patch_one() {
    local f=$1
    is_elf32 "$f"    || { n_skipped=$((n_skipped+1)); return; }
    if ! links_libc5 "$f"; then
        echo "  skip (already glibc or not libc5): $(basename "$f")"
        n_skipped=$((n_skipped+1)); return
    fi
    python3 - "$f" <<'PY'
import sys
f = sys.argv[1]
d = open(f, 'rb').read()
d = d.replace(b'/lib/ld-linux.so.1\x00', b'/lib/ld-linux.so.2\x00')
d = d.replace(b'libc.so.5\x00', b'retro5.so\x00')
d = d.replace(b'libm.so.5\x00', b'libm.so.6\x00')
open(f, 'wb').write(d)
PY
    python3 "$HIDESYM" "$f" errno >/dev/null 2>&1 || true
    echo "  retargeted: $(basename "$f")  [$(readelf -d "$f" 2>/dev/null | awk -F'[][]' '/NEEDED/{printf "%s ",$2}')]"
    n_patched=$((n_patched+1))
}

if [ "${1:-}" = "--scan" ]; then
    dir=${2:?usage: retarget.sh --scan <dir>}
    while IFS= read -r f; do patch_one "$f"; done < <(find "$dir" -type f 2>/dev/null)
else
    [ $# -ge 1 ] || { echo "usage: retarget.sh <file>... | --scan <dir>"; exit 1; }
    for f in "$@"; do patch_one "$f"; done
fi

echo "== retargeted $n_patched, skipped $n_skipped =="
