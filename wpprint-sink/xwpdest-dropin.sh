#!/bin/sh
# SPDX-License-Identifier: MIT
# xwpdest — retro5 modern-print drop-in (installed OVER WordPerfect's xwpdest by
# the optional modern print system; the original is kept as xwpdest.orig).
#
# WordPerfect's Print dialog "Select…" button, and its printer setup, run this
# binary. We intercept ONLY the interactive printer-select/setup call and open
# our CUPS-backed dialog; every other invocation (the job/spool path, and any
# form we don't recognise) falls through to the original xwpdest UNCHANGED — so
# printing is never broken by installing this.
#
# Selection signature (from RE): a settings file (*.set) + the `_wq` token, with
# a DISPLAY. When that matches we launch wpprinter-dialog.py (which records the
# chosen CUPS printer in $WPCOM/wpsink.dest that the sink/lp path reads).
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIALOG="$HERE/wpprinter-dialog.py"
ORIG="$HERE/xwpdest.orig"

is_select=0
have_set=0
for a in "$@"; do
    case "$a" in
        _wq) is_select=1 ;;
        *.set|*.wpc8x.set) have_set=1 ;;
    esac
done

# open our dialog only on a clear interactive select call; otherwise be native
if [ "$is_select" = 1 ] && [ "$have_set" = 1 ] && [ -n "${DISPLAY:-}" ] \
   && [ -f "$DIALOG" ] && command -v python3 >/dev/null 2>&1; then
    # WP is an X11/Motif app (real X or XWayland). Force our GTK dialog onto the
    # SAME X server so it can be transient/modal to WP's window — a native
    # Wayland client couldn't parent across to WP. Pass WP's window id if we have
    # it ($WINDOWID; the exact CLIENT_WINDOW hand-off is confirmed by capture).
    parent_arg=""
    [ -n "${WINDOWID:-}" ] && parent_arg="--parent-xid $WINDOWID"
    # shellcheck disable=SC2086  # WINDOWID is a numeric window id, no splitting risk
    GDK_BACKEND=x11 python3 "$DIALOG" $parent_arg
    # WP keeps "Passthru PostScript" as its printer; we only changed the CUPS
    # destination behind it, so there's nothing to hand back. Exit success.
    exit 0
fi

# fall through to the real xwpdest (job/spool path, unknown modes, or no dialog)
if [ -x "$ORIG" ]; then
    exec "$ORIG" "$@"
fi
# no original present (shouldn't happen after install) — do nothing, succeed
exit 0
