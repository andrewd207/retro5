#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# build-tree.sh - decompress the WP8 binaries+data into a real install root,
# using wpdecom2 and the ship manifest. Then retarget every libc5 ELF32.
#
#   ./build-tree.sh [ROOT]     default ROOT=/usr/wplinux
set -u
MEDIA=/home/andrew/Programming/Projects/wordperfect-8-lin
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${1:-/usr/wplinux}
DEC=$MEDIA/wpdecom2
SHIP=$MEDIA/shared/ship

[ -x "$DEC" ] || { echo "need $DEC (make wpdecom2 first)"; exit 1; }

# platform-filter the manifest (linux + ALL sections), drop comments/blanks
sed -n -e '/^#ifdef.*linux$/,/^#endif.*linux$/p' \
       -e '/^#ifdef ALL$/,/^#endif ALL$/p' "$SHIP" \
  | sed -e '/^#/d' -e '/^[[:space:]]*$/d' > /tmp/ship.linux

dec=0 cp=0 miss=0
while read -r J1 Nam1 Dir1 Opt Perm Dir2 Nam2; do
    [ -n "${Nam2:-}" ] || continue
    Type=${Opt: -1}
    case "$Type" in c|x|b|d) ;; *) continue ;; esac      # decompressable entries
    case "$Dir1" in bin|dat|lng|lng/*) ;; *) continue ;; esac
    src="$MEDIA/linux/$Dir1/$Nam1"
    [ -f "$src" ] || { miss=$((miss+1)); continue; }
    mkdir -p "$ROOT/$Dir2"
    dst="$ROOT/$Dir2/$Nam2"
    # WP resource files (.drs display-resource, .lrs) are read by WP in their
    # native compressed \xffWPC form at RUNTIME (xwp's own loader parses the
    # header + LZSS). Decompressing them makes xwp reject the file (magic
    # mismatch -> fatal "wp.drs" dialog). Ship these compressed, verbatim.
    case "$Nam2" in
        *.drs|*.lrs) cp "$src" "$dst"; cp=$((cp+1)); chmod "$Perm" "$dst" 2>/dev/null || true; continue ;;
    esac
    "$DEC" "$src" "$dst" 2>/dev/null
    rc=$?
    if [ "$rc" = 2 ]; then cp "$src" "$dst"; cp=$((cp+1))
    elif [ "$rc" != 0 ]; then miss=$((miss+1)); continue
    else dec=$((dec+1)); fi
    chmod "$Perm" "$dst" 2>/dev/null || true
done < /tmp/ship.linux
echo "== tree built in $ROOT: decompressed $dec, copied $cp, missing/failed $miss =="

echo "== retargeting every libc5 ELF32 in $ROOT =="
bash "$HERE/retarget.sh" --scan "$ROOT" | tail -5

# same-length in-place binary patches (must run AFTER retarget.sh)
bash "$HERE/apply-patches.sh" "$ROOT"

# make the shim findable + admin/runtime markers
cp "$HERE/build/retro5.so" "$ROOT/shbin10/" 2>/dev/null
: > "$ROOT/shlib10/.wpc.admin" 2>/dev/null
mkdir -p "$ROOT/wplib"; : > "$ROOT/wplib/.def.lang" 2>/dev/null; : > "$ROOT/wplib/.license" 2>/dev/null
echo "== done: $ROOT/shbin10 has $(ls "$ROOT/shbin10" 2>/dev/null | wc -l) files =="
