#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# detect-static-x11.sh <dir> - find ELF32 binaries that have X11 compiled in
# STATICALLY (contain Xlib/Xtrans code) but do NOT dynamically link libX11.
# These use ancient 1998 Xtrans that fails against a modern X server
# (e.g. mwp: "SocketUNIXConnect: Missing port specification").
set -u
dir=${1:?usage: detect-static-x11.sh <dir>}
found=0
while IFS= read -r f; do
    file -b "$f" 2>/dev/null | grep -q '^ELF 32-bit' || continue
    # if it dynamically links libX11, it's fine (uses modern Xlib) - skip
    readelf -d "$f" 2>/dev/null | grep -q 'libX11' && continue
    # does it contain statically-linked Xlib/Xtrans code?
    tag=$(strings "$f" 2>/dev/null | grep -oE '_X11TransSocket|SocketUNIXConnect|_X11TransConnect|XOpenDisplay|/tmp/\.X11-unix' | head -1)
    if [ -n "$tag" ]; then
        echo "STATIC-X11: $(basename "$f")   (marker: $tag)"
        found=$((found+1))
    fi
done < <(find "$dir" -type f 2>/dev/null)
echo "== $found binaries with statically-linked X11 =="
