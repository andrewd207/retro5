#!/bin/sh
# SPDX-License-Identifier: MIT
# install.sh — enable (or remove) the retro5 modern print system in a WP tree.
#
#   sudo ./install.sh WP_ROOT               # enable the CUPS-backed print dialog
#   sudo ./install.sh --uninstall WP_ROOT   # restore the original xwpdest
#
# Installs our tools into <WP_ROOT>/shbin10 and swaps xwpdest for a drop-in that
# opens the CUPS dialog on printer-select and falls through to the ORIGINAL
# xwpdest (kept as xwpdest.orig) for the print/spool path — fully reversible.
set -eu

usage() { echo "usage: sudo $0 [--uninstall] WP_ROOT"; exit 2; }
UNINSTALL=0; ROOT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage ;;
        -*) echo "unknown option: $1" >&2; usage ;;
        *) [ -z "$ROOT" ] || usage; ROOT="$1" ;;
    esac
    shift
done
[ -n "$ROOT" ] || usage
SHBIN="$ROOT/shbin10"
[ -d "$SHBIN" ] || { echo "error: $SHBIN not found — '$ROOT' isn't a WP tree" >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$UNINSTALL" = 1 ]; then
    if [ -f "$SHBIN/xwpdest.orig" ]; then
        mv -f "$SHBIN/xwpdest.orig" "$SHBIN/xwpdest"
        echo "-- restored the original xwpdest"
    fi
    rm -f "$SHBIN/wpprinter-dialog.py" "$SHBIN/wpselect" "$SHBIN/wpsink"
    echo "-- removed the modern print tools"
    echo "Done. WordPerfect printing is back to stock."
    exit 0
fi

command -v python3 >/dev/null 2>&1 || echo "warning: python3 not found — the dialog needs it"
echo "-- building wpsink + wpselect"
make -C "$HERE" wpsink wpselect >/dev/null

echo "-- installing tools into $SHBIN"
install -m0755 "$HERE/wpselect"            "$SHBIN/wpselect"
install -m0755 "$HERE/wpsink"              "$SHBIN/wpsink"
install -m0755 "$HERE/wpprinter-dialog.py" "$SHBIN/wpprinter-dialog.py"

# back up the real xwpdest exactly once (never back up our own drop-in over it)
if [ -e "$SHBIN/xwpdest" ] && [ ! -e "$SHBIN/xwpdest.orig" ]; then
    if grep -q 'retro5 modern-print drop-in' "$SHBIN/xwpdest" 2>/dev/null; then
        echo "-- xwpdest is already our drop-in (leaving xwpdest.orig as-is)"
    else
        mv "$SHBIN/xwpdest" "$SHBIN/xwpdest.orig"
        echo "-- backed up the original xwpdest -> xwpdest.orig"
    fi
fi
install -m0755 "$HERE/xwpdest-dropin.sh" "$SHBIN/xwpdest"

cat <<EOF

Done. WordPerfect's Print > Select… now opens the CUPS printer dialog; the
print/spool path still uses the original xwpdest. Pick a printer with the dialog
(or: wpselect --set NAME). Revert any time:
    sudo $0 --uninstall $ROOT
EOF
