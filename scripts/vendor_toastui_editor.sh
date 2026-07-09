#!/usr/bin/env bash
# Refresh the vendored Toast UI Editor bundle used by the kanban rich-text editor.
#
# The runtime loads these files from /assets/vendor instead of a third-party CDN.
# Run this only to bump the pinned version; commit the regenerated assets.
#
#   scripts/vendor_toastui_editor.sh [version]
#
# Default version is pinned below. The generated files are:
#   assets/vendor/toastui-editor-all.min.js
#   assets/vendor/toastui-editor.min.css
set -euo pipefail

VERSION="${1:-3.2.2}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$HERE/assets/vendor"
SCRIPT_PATH="$VENDOR_DIR/toastui-editor-all.min.js"
CSS_PATH="$VENDOR_DIR/toastui-editor.min.css"
BASE_URL="https://uicdn.toast.com/editor/${VERSION}"

mkdir -p "$VENDOR_DIR"
echo "Fetching Toast UI Editor ${VERSION} ..."
curl -fsSL "$BASE_URL/toastui-editor-all.min.js" -o "$SCRIPT_PATH"
curl -fsSL "$BASE_URL/toastui-editor.min.css" -o "$CSS_PATH"

if ! grep -q "@toast-ui/editor" "$SCRIPT_PATH"; then
  echo "ERROR: downloaded script does not look like Toast UI Editor" >&2
  exit 1
fi

if ! grep -q "@toast-ui/editor" "$CSS_PATH"; then
  echo "ERROR: downloaded CSS does not look like Toast UI Editor" >&2
  exit 1
fi

echo "Vendored Toast UI Editor ${VERSION}:"
echo "  $SCRIPT_PATH"
echo "  $CSS_PATH"
