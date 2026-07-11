#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
# Register the "Install WordPerfect 8" launcher in your desktop menu.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
DEST="$HOME/.local/share/applications"
mkdir -p "$DEST"
# rewrite Exec to this checkout's absolute path, then install
sed "s#^Exec=.*#Exec=python3 $HERE/wp8_install_gui.py#" \
    "$HERE/wordperfect8-installer.desktop" > "$DEST/wordperfect8-installer.desktop"
chmod 644 "$DEST/wordperfect8-installer.desktop"
update-desktop-database "$DEST" 2>/dev/null || true
echo "Installed: $DEST/wordperfect8-installer.desktop"
echo "Look for 'Install WordPerfect 8' in your app menu."
