#!/usr/bin/env bash
# Refresh the vendored Toast UI Editor bundle used by the kanban rich-text editor.
#
# The runtime loads these files from /assets/vendor instead of a third-party CDN.
# Run this only to bump the pinned version; commit the regenerated assets.
#
#   scripts/vendor_toastui_editor.sh [version] [expected_js_sha256] [expected_css_sha256]
#
# Default version is pinned below. The generated files are:
#   assets/vendor/toastui-editor-all.min.js
#   assets/vendor/toastui-editor.min.css
set -euo pipefail

VERSION="${1:-3.2.2}"
EXPECTED_JS_SHA256="${2:-dd7ebbf0e462a0ced9d1cf86126fdcdad3c3d047a2ad447e06d54b27a76acce4}"
EXPECTED_CSS_SHA256="${3:-db0201d4afe12fe07cd3c23a3d6cf735061add6b404901bc7164d56bb043f4cd}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$HERE/assets/vendor"
SCRIPT_PATH="$VENDOR_DIR/toastui-editor-all.min.js"
CSS_PATH="$VENDOR_DIR/toastui-editor.min.css"
BASE_URL="https://uicdn.toast.com/editor/${VERSION}"

mkdir -p "$VENDOR_DIR"
echo "Fetching Toast UI Editor ${VERSION} ..."
TMP_SCRIPT="$(mktemp)"
TMP_CSS="$(mktemp)"
trap 'rm -f "$TMP_SCRIPT" "$TMP_CSS"' EXIT
curl -fsSL "$BASE_URL/toastui-editor-all.min.js" -o "$TMP_SCRIPT"
curl -fsSL "$BASE_URL/toastui-editor.min.css" -o "$TMP_CSS"

ACTUAL_JS_SHA256="$(sha256sum "$TMP_SCRIPT" | awk '{print $1}')"
ACTUAL_CSS_SHA256="$(sha256sum "$TMP_CSS" | awk '{print $1}')"
if [[ "$ACTUAL_JS_SHA256" != "$EXPECTED_JS_SHA256" || "$ACTUAL_CSS_SHA256" != "$EXPECTED_CSS_SHA256" ]]; then
  echo "ERROR: Toast UI Editor SHA-256 mismatch" >&2
  echo "JavaScript expected/actual: $EXPECTED_JS_SHA256 / $ACTUAL_JS_SHA256" >&2
  echo "CSS expected/actual:        $EXPECTED_CSS_SHA256 / $ACTUAL_CSS_SHA256" >&2
  exit 1
fi
mv "$TMP_SCRIPT" "$SCRIPT_PATH"
mv "$TMP_CSS" "$CSS_PATH"

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
echo "Update assets/vendor/manifest.json with the reviewed source hashes."
