#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# collect-imports.sh <dir> - union of every ELF32's undefined symbols, so we
# know the COMPLETE set of functions the shim must provide across the whole
# WordPerfect suite (not one binary at a time).
#
# Splits the union into: provided-by-libc5 (the shim's job), and of those,
# which the shim already exports vs. is still MISSING.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: collect-imports.sh <dir-of-elf32>}
LIBC5=/usr/i386-compat-gnulibc1/lib/libc.so.5
SHIM=$HERE/build/retro5.so

und=/tmp/all_und.txt; : > "$und"
files=0
while IFS= read -r f; do
    file -b "$f" 2>/dev/null | grep -q '^ELF 32-bit' || continue
    files=$((files+1))
    readelf --dyn-syms "$f" 2>/dev/null \
        | awk '$7=="UND"&&$8{sub(/@.*/,"",$8);print $8}'
done < <(find "$dir" -type f 2>/dev/null) | sort -u > "$und"

echo "scanned $files ELF32 binaries"
echo "distinct imported symbols (all libs): $(wc -l < "$und")"

# libc.so.5-provided subset == the shim's responsibility
readelf --dyn-syms "$LIBC5" 2>/dev/null | awk '$7!="UND"&&$8{sub(/@.*/,"",$8);print $8}' \
    | sort -u > /tmp/libc5_exp.txt
comm -12 "$und" /tmp/libc5_exp.txt > /tmp/need_libc.txt
echo "libc.so.5 symbols needed across the suite: $(wc -l < /tmp/need_libc.txt)"

# what the shim already provides
if [ -f "$SHIM" ]; then
    readelf --dyn-syms "$SHIM" 2>/dev/null | awk '($4=="FUNC"||$4=="OBJECT")&&$8{print $8}' \
        | sort -u > /tmp/shim_exp.txt
    miss=$(comm -23 /tmp/need_libc.txt /tmp/shim_exp.txt)
    echo "already covered by shim: $(comm -12 /tmp/need_libc.txt /tmp/shim_exp.txt | wc -l)"
    echo "STILL MISSING ($(printf '%s\n' "$miss" | grep -c .)):"
    printf '%s\n' "$miss" | sed 's/^/  /'
else
    echo "(build retro5.so first to see what's missing)"
    echo "full libc list saved to /tmp/need_libc.txt"
fi
