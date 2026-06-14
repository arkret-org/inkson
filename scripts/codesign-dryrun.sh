#!/usr/bin/env bash
# Reproducible codesign / notarization DRY-RUN for yougen desktop.
#
# NOT FOR PRODUCTION USE. This script never submits to Apple, Microsoft
# timestamp authorities, or external signing services. It records what the
# live signing strand WOULD do given the current host environment.
#
# P5 (2026-05-27): POSIX sibling of scripts/codesign-dryrun.ps1.

set -euo pipefail

SCRIPT_VERSION="P5.codesign-dryrun.v1"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

ARTIFACT_PATH="${1:-target/release/yougen}"
DIST_DIR="${YOUGEN_DIST_DIR:-dist/signing}"
NO_BUILD="${YOUGEN_NO_BUILD:-0}"

mkdir -p "${DIST_DIR}"

if [[ ! -f "${ARTIFACT_PATH}" && "${NO_BUILD}" != "1" ]]; then
    echo "Artifact missing; running cargo build --release"
    cargo build --release
fi

UNAME_S="$(uname -s)"
case "${UNAME_S}" in
    Darwin) HOST_OS="darwin" ;;
    Linux) HOST_OS="linux" ;;
    *) HOST_OS="other" ;;
esac

ARTIFACT_EXISTS="false"
ARTIFACT_SHA256="null"
if [[ -f "${ARTIFACT_PATH}" ]]; then
    ARTIFACT_EXISTS="true"
    if command -v sha256sum >/dev/null 2>&1; then
        ARTIFACT_SHA256="\"$(sha256sum "${ARTIFACT_PATH}" | awk '{print $1}')\""
    elif command -v shasum >/dev/null 2>&1; then
        ARTIFACT_SHA256="\"$(shasum -a 256 "${ARTIFACT_PATH}" | awk '{print $1}')\""
    fi
fi

PLATFORM_JSON=""
if [[ "${HOST_OS}" == "darwin" ]]; then
    CODESIGN_AVAIL="false"; command -v codesign >/dev/null 2>&1 && CODESIGN_AVAIL="true"
    XCRUN_AVAIL="false"; command -v xcrun >/dev/null 2>&1 && XCRUN_AVAIL="true"
    IDENTITY_PRESENT="false"
    [[ -n "${YOUGEN_MACOS_SIGN_IDENTITY:-}" ]] && IDENTITY_PRESENT="true"
    NOTARY_PRESENT="false"
    if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" ]] && \
       { [[ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]] || [[ -n "${APPLE_KEYCHAIN_PROFILE:-}" ]]; }; then
        NOTARY_PRESENT="true"
    fi
    WOULD_SIGN="false"
    [[ "${ARTIFACT_EXISTS}" == "true" && "${CODESIGN_AVAIL}" == "true" && "${IDENTITY_PRESENT}" == "true" ]] && WOULD_SIGN="true"
    PLATFORM_JSON=$(cat <<EOF
    {
      "platform": "macos",
      "codesign_available": ${CODESIGN_AVAIL},
      "signing_identity_present": ${IDENTITY_PRESENT},
      "notarytool_available": ${XCRUN_AVAIL},
      "notary_input_present": ${NOTARY_PRESENT},
      "would_sign": ${WOULD_SIGN},
      "would_submit_notary": false,
      "would_staple": false,
      "notes": [
        "Local plan validates codesign/notarytool inputs only.",
        "Never runs notarytool submit or stapler in dry-run mode."
      ]
    }
EOF
)
else
    GPG_AVAIL="false"; command -v gpg >/dev/null 2>&1 && GPG_AVAIL="true"
    TARBALL="${DIST_DIR}/yougen-linux-x64.tar.gz"
    WOULD_TAR="${ARTIFACT_EXISTS}"
    WOULD_SIGN="false"
    [[ "${ARTIFACT_EXISTS}" == "true" && "${GPG_AVAIL}" == "true" ]] && WOULD_SIGN="true"
    PLATFORM_JSON=$(cat <<EOF
    {
      "platform": "linux",
      "gpg_available": ${GPG_AVAIL},
      "tarball": "${TARBALL}",
      "would_tar": ${WOULD_TAR},
      "would_sign": ${WOULD_SIGN},
      "detached_signature_path": "${TARBALL}.asc",
      "package_formats": ["tar.gz", "deb", "rpm", "AppImage", "Flatpak"],
      "notes": [
        "Plan only — no tar / gpg invocation in dry-run mode.",
        "Real package builds live in scripts/linux-package-local.ps1."
      ]
    }
EOF
)
fi

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"

EVIDENCE_PATH="${DIST_DIR}/codesign-dryrun.json"
cat > "${EVIDENCE_PATH}" <<EOF
{
  "schema": "yougen/codesign-dryrun/v1",
  "script_version": "${SCRIPT_VERSION}",
  "generated_at": "${GENERATED_AT}",
  "host": {
    "os": "${HOST_OS}",
    "uname": "${UNAME_S}"
  },
  "artifact": {
    "path": "${ARTIFACT_PATH}",
    "exists": ${ARTIFACT_EXISTS},
    "sha256": ${ARTIFACT_SHA256}
  },
  "production_use": false,
  "remote_submit": false,
  "timestamp_server": false,
  "transparency_log": false,
  "platforms": [
${PLATFORM_JSON}
  ],
  "notes": [
    "NOT FOR PRODUCTION USE — this is a reproducible dry-run only.",
    "No remote endpoint (Apple notarytool, MS timestamp authority, GPG keyserver) is contacted.",
    "Real signing happens through a separate manual strand with a paid Developer ID / EV cert."
  ]
}
EOF

echo "Wrote codesign dry-run evidence to ${EVIDENCE_PATH}"
echo "NOT FOR PRODUCTION USE — see SECURITY.md for the real signing strand."
