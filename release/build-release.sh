#!/bin/bash
# SPDX-License-Identifier: MIT
# build-release.sh — assemble a retro5 release bundle (freshly-built shim +
# scripts + full installer) ready to attach to a GitHub release.
#
#   ./build-release.sh <version>       e.g. ./build-release.sh v1.0
#
# Produces, under release/dist/:
#   retro5-wp8-<version>.tar.gz   the full bundle (both install approaches)
#   retro5.so                     the standalone shim, for updating an install
#   SHA256SUMS
set -euo pipefail

VER="${1:?usage: build-release.sh <version, e.g. v1.0>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # release/
REPO="$(cd "$HERE/.." && pwd)"                            # wp8-modern/
OUT="$HERE/dist"
NAME="retro5-wp8-$VER"
STAGE="$(mktemp -d)/$NAME"

echo "== building retro5.so =="
make -C "$REPO/retro5" clean >/dev/null 2>&1 || true
make -C "$REPO/retro5" >/dev/null
[ -f "$REPO/retro5/retro5.so" ] || { echo "build failed: no retro5.so"; exit 1; }

echo "== staging $NAME =="
mkdir -p "$STAGE/installer"
install -m0755 "$HERE/retro5-setup.sh"     "$STAGE/retro5-setup.sh"
install -m0755 "$REPO/tools/retarget.py"   "$STAGE/retarget.py"
install -m0644 "$REPO/installer/XKeysymDB" "$STAGE/XKeysymDB"
install -m0644 "$REPO/retro5/retro5.so"    "$STAGE/retro5.so"
install -m0644 "$HERE/README.md"           "$STAGE/README.md"
install -m0644 "$REPO/LICENSE"             "$STAGE/LICENSE"
# approach B: the full installer, verbatim
cp -r "$REPO/installer/." "$STAGE/installer/"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "== packaging =="
mkdir -p "$OUT"
tar -C "$(dirname "$STAGE")" -czf "$OUT/$NAME.tar.gz" "$NAME"
install -m0644 "$REPO/retro5/retro5.so" "$OUT/retro5.so"
( cd "$OUT" && sha256sum "$NAME.tar.gz" retro5.so > SHA256SUMS )

echo "== release assets in $OUT =="
ls -la "$OUT"
echo
echo "Attach these to the GitHub release:"
echo "  $OUT/$NAME.tar.gz"
echo "  $OUT/retro5.so"
echo
echo "e.g.:  gh release create $VER $OUT/$NAME.tar.gz $OUT/retro5.so \\"
echo "          --title 'retro5 $VER' --notes-file <notes>"
