#!/usr/bin/env bash
# Refresh the vendored livekit-client UMD bundle used by the WebRTC media path.
#
# Both the web (wasm) shim and the desktop driver load the SDK from this
# vendored file instead of a runtime CDN, so the call surface works offline and
# has no third-party single point of failure. Run this only to bump the pinned
# version; commit the regenerated assets.
#
#   scripts/vendor_livekit.sh [version] [expected_sha256]
#
# Default version is pinned below. The generated files are:
#   assets/vendor/livekit-client.umd.min.js  (raw UMD, included by native.rs)
#   assets/livekit_vendor.js                 (ES-module wrapper, imported by the wasm shim)
set -euo pipefail

VERSION="${1:-2.19.2}"
EXPECTED_SHA256="${2:-cc4d7f3ee245316debdb9eff1b6851da0a7b13ba9509532a727884afe9e5e882}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$HERE/assets/vendor"
UMD_PATH="$VENDOR_DIR/livekit-client.umd.min.js"
WRAPPER_PATH="$HERE/assets/livekit_vendor.js"
URL="https://cdn.jsdelivr.net/npm/livekit-client@${VERSION}/dist/livekit-client.umd.min.js"

mkdir -p "$VENDOR_DIR"
echo "Fetching livekit-client@${VERSION} ..."
TMP_PATH="$(mktemp)"
trap 'rm -f "$TMP_PATH"' EXIT
curl -fsSL "$URL" -o "$TMP_PATH"

ACTUAL_SHA256="$(sha256sum "$TMP_PATH" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo "ERROR: livekit-client SHA-256 mismatch" >&2
  echo "expected: $EXPECTED_SHA256" >&2
  echo "actual:   $ACTUAL_SHA256" >&2
  exit 1
fi
mv "$TMP_PATH" "$UMD_PATH"

if ! grep -q "LivekitClient" "$UMD_PATH"; then
  echo "ERROR: downloaded UMD does not expose the LivekitClient global" >&2
  exit 1
fi

{
  echo "// AUTO-GENERATED — do not edit by hand."
  echo "// Vendored livekit-client UMD (pinned ${VERSION}), wrapped as an ES module so the"
  echo "// wasm shim can import it directly. The UMD body self-registers"
  echo "// \`window.LivekitClient\`; no network fetch, no CDN. Refresh with"
  echo "// scripts/vendor_livekit.sh."
  echo "/* eslint-disable */"
  echo "export const LIVEKIT_VENDOR_VERSION = \"${VERSION}\";"
  cat "$UMD_PATH"
  printf '\n%s\n' 'export const LIVEKIT_VENDORED = true;'
} > "$WRAPPER_PATH"

echo "Vendored livekit-client@${VERSION}:"
echo "  $UMD_PATH"
echo "  $WRAPPER_PATH"
echo "Update assets/vendor/manifest.json with the reviewed source and generated file hashes."
