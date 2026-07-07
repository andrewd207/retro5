#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
#
# retro5-setup.sh — make an EXISTING WordPerfect 8/8.1 for Linux tree run on a
# modern 64-bit glibc system, in place, via the retro5 libc5->glibc shim.
#
# Use this if you already have a WP tree on disk — e.g. laid down by the
# community installer at https://xwp8users.com/packages/wp81in.sh, whose root is
# /usr/lib/wp8. It does NOT install WordPerfect; it converts a tree you already
# have. To install WP from your own media/ISO/.deb into a fresh tree instead,
# use the full installer (installer/wp8_installer.py) — see README.
#
# Idempotent and safe to re-run. Needs root (writes under the WP tree and into
# the system 32-bit library dir).
#
#   sudo ./retro5-setup.sh [--install-deps] [WP_ROOT]   # WP_ROOT defaults to /usr/lib/wp8
#
# --install-deps detects the package manager (apt/dnf/pacman/zypper) and installs
# the 32-bit runtime libraries WP needs — the i386 glibc plus the 32-bit X libs
# (some bundled binaries link X even in the "static-X" editions) — then continues.
#
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="/usr/lib/i386-linux-gnu"           # trusted dir the 32-bit loader searches
XKDB_SYS="/usr/X11R6/lib/X11/XKeysymDB"    # the path WP's bundled libX11 hardcodes

die(){ echo "error: $*" >&2; exit 1; }
usage(){ cat <<U
usage: sudo $0 [--install-deps] [WP_ROOT]

  --install-deps   detect the package manager (apt/dnf/pacman/zypper) and
                   install the 32-bit runtime libraries WP needs, then convert.
  WP_ROOT          WordPerfect tree to convert (default /usr/lib/wp8).
U
}

INSTALL_DEPS=0
ROOT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --install-deps) INSTALL_DEPS=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1 (see --help)" ;;
        *) [ -z "$ROOT" ] || die "unexpected extra argument: $1"; ROOT="$1" ;;
    esac
    shift
done
ROOT="${ROOT:-/usr/lib/wp8}"

# Install the 32-bit runtime: the i386 glibc (always) PLUS the 32-bit X libs.
# The X libs are installed unconditionally because WP editions vary — the 8.0
# build's xwp needs them, and in the other editions some bundled/helper binaries
# link X dynamically (not everything is static-X). They're small and harmless.
install_deps(){
    echo "==> installing 32-bit runtime libraries (glibc + X libs)"
    if command -v apt-get >/dev/null 2>&1; then
        dpkg --add-architecture i386
        apt-get update
        apt-get install -y libc6:i386
        # libxt6 was renamed libxt6t64 on Ubuntu 24.04+/Debian 13 (time_t transition)
        apt-get install -y libx11-6:i386 libxpm4:i386 libxt6:i386 \
          || apt-get install -y libx11-6:i386 libxpm4:i386 libxt6t64:i386
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y glibc.i686 libX11.i686 libXpm.i686 libXt.i686
    elif command -v pacman >/dev/null 2>&1; then
        grep -q '^\[multilib\]' /etc/pacman.conf 2>/dev/null \
          || echo "note: if this fails, enable the [multilib] repo in /etc/pacman.conf first"
        pacman -S --needed --noconfirm lib32-glibc lib32-libx11 lib32-libxpm lib32-libxt
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install glibc-32bit libX11-6-32bit libXpm4-32bit libXt6-32bit
    else
        die "no supported package manager (apt/dnf/pacman/zypper) found — install the 32-bit libs by hand (see README)"
    fi
    echo "==> 32-bit runtime libraries installed"; echo
}

[ "$(id -u)" = 0 ]         || die "run me with sudo (I write to $ROOT and $LIBDIR)"
command -v python3 >/dev/null || die "python3 is required"
[ -f "$HERE/retro5.so" ]   || die "retro5.so must sit next to this script"
[ -f "$HERE/retarget.py" ] || die "retarget.py must sit next to this script"

if [ "$INSTALL_DEPS" = 1 ]; then install_deps; fi

[ -d "$ROOT" ]            || die "WP root '$ROOT' not found — pass yours as the first argument"
[ -e "$ROOT/wpbin/xwp" ] || die "'$ROOT/wpbin/xwp' missing — '$ROOT' doesn't look like a WP8 tree"

# 32-bit runtime check: retargeting points xwp at /lib/ld-linux.so.2, so WP needs
# the i386 glibc. Warn early (with the fix) rather than let WP fail to launch.
if [ ! -e /lib/ld-linux.so.2 ] && [ ! -e /lib/i386-linux-gnu/ld-linux.so.2 ]; then
    echo "warning: the 32-bit loader /lib/ld-linux.so.2 is not installed — WordPerfect"
    echo "         will not start until you add the i386 glibc. Re-run me with"
    echo "         --install-deps to do it automatically, or on Debian/Ubuntu/Mint:"
    echo "           sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install libc6:i386"
    echo "         (Fedora: glibc.i686 · Arch: lib32-glibc · openSUSE: glibc-32bit)"
    echo "         See the README 'Requirements' section. Continuing the conversion anyway."
    echo
fi

echo "==> retro5 setup for WordPerfect at: $ROOT"

# 1. Retarget every libc5 ELF32 in the tree: libc.so.5->retro5.so,
#    libm.so.5->libm.so.6, /lib/ld-linux.so.1->.2, and hide the copy-relocated
#    errno. Same-length in-place byte edits — nothing moves, .hash stays valid.
echo "-- retargeting binaries under $ROOT"
python3 "$HERE/retarget.py" --scan "$ROOT"

# 2. Install the shim where the 32-bit loader finds it by default (no
#    LD_LIBRARY_PATH needed for anyone).
echo "-- installing retro5.so -> $LIBDIR"
install -d "$LIBDIR"
install -m0644 "$HERE/retro5.so" "$LIBDIR/retro5.so"
ldconfig 2>/dev/null || true

# 3. Morph patch: NOP the out-of-bounds strcpy in mor_read_entry, or WP SIGSEGVs
#    during as-you-type morphology. Offset-based against known builds; idempotent
#    and a no-op if the signature isn't present.
echo "-- morph patch (xwp)"
python3 - "$ROOT/wpbin/xwp" <<'PY'
import sys
NOP = bytes.fromhex("9090909090")
SIGS = [(0x1e8dda, "e82997e1ff"),   # WP 8.1 / 8.16MB static-X build
        (0x211cff, "e8fc53dfff")]   # WP 8.0.0076 dynamic-X build
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); changed = matched = False
for off, exph in SIGS:
    exp = bytes.fromhex(exph)
    if off + 5 <= len(b):
        cur = bytes(b[off:off + 5])
        if cur == NOP:
            matched = True; print(f"   already patched @0x{off:x}")
        elif cur == exp:
            b[off:off + 5] = NOP; changed = matched = True; print(f"   applied  @0x{off:x}")
if changed: open(p, "wb").write(b)
if not matched: print("   no known buggy signature at the expected offset (left untouched)")
PY

# 4. XKeysymDB: WP's 1998 libX11 resolves Motif virtual keysyms (osfDelete,
#    osfLeft, ...) via this file, which modern X no longer ships — without it
#    Delete/BackSpace/arrows self-insert garbage in dialog text fields. Install
#    it at the exact path libX11 hardcodes, so NO launcher env change is needed.
echo "-- XKeysymDB -> $XKDB_SYS"
install -Dm0644 "$HERE/XKeysymDB" "$XKDB_SYS"
[ -d "$ROOT/shlib10" ] && install -m0644 "$HERE/XKeysymDB" "$ROOT/shlib10/XKeysymDB"

# 5. passpost.prs: WP defaults its printer to "passpost" and errors
#    "File not found ... passpost.prs" if it's absent. Seed it from default.prs.
if [ ! -e "$ROOT/shlib10/passpost.prs" ] && [ -f "$ROOT/shlib10/default.prs" ]; then
    cp "$ROOT/shlib10/default.prs" "$ROOT/shlib10/passpost.prs"
    echo "-- created $ROOT/shlib10/passpost.prs"
fi

cat <<EOF

==> Done. WordPerfect at $ROOT now runs on this system's glibc via retro5.

If your launcher doesn't already set them, WP also wants:
    export XLOCALEDIR=/usr/share/X11/locale   # ancient static Xlib -> modern locale dir
    export WPC=$ROOT
(The keys fix needs no env — XKeysymDB was installed at libX11's default path.)

Re-run this script any time (e.g. after updating retro5.so); it's idempotent.
EOF
