#!/usr/bin/env sh
# Source before Cargo checks so all Windows/WSL cache writes stay on D.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) inkson_cache="D:/BuildCache/inkson-glory"; inkson_cargo_home="D:/BuildCache/cargo" ;;
  *) if [ -n "${WSL_DISTRO_NAME:-}" ]; then
       awk '$2 == "/mnt/d" && toupper($1) ~ /^D:/ { found=1 } END { exit !found }' /proc/mounts || { echo "Verify the D: /mnt/d mount before building" >&2; return 1; }
       inkson_cache="/mnt/d/BuildCache/inkson-glory"; inkson_cargo_home="/mnt/d/BuildCache/cargo"
     else inkson_cache="${CARGO_TARGET_DIR:-target}"; inkson_cargo_home="${CARGO_HOME:-}"; fi ;;
esac
if [ -n "${inkson_cargo_home:-}" ]; then export CARGO_HOME="${CARGO_HOME:-$inkson_cargo_home}"; fi
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) inkson_default_target="$inkson_cache/target" ;; *) if [ -n "${WSL_DISTRO_NAME:-}" ]; then inkson_default_target="$inkson_cache/target"; else inkson_default_target="$inkson_cache"; fi ;; esac
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$inkson_default_target}"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    for inkson_output in "$CARGO_TARGET_DIR" "$CARGO_HOME"; do
      case "$inkson_output" in
        [Dd]:/*|[Dd]:\\*|/[Dd]/*) ;;
        *) echo "Windows Cargo output and cache must resolve to D:" >&2; return 1 ;;
      esac
    done ;;
  *) if [ -n "${WSL_DISTRO_NAME:-}" ]; then
       for inkson_output in "$CARGO_TARGET_DIR" "$CARGO_HOME"; do
         inkson_resolved_output=$(realpath -m -- "$inkson_output") || return 1
         case "$inkson_resolved_output" in /mnt/d/*) ;; *) echo "WSL Cargo output and cache must remain on the verified D: mount" >&2; return 1 ;; esac
       done
     fi ;;
esac
mkdir -p "$inkson_cache/tmp"
export TEMP="$inkson_cache/tmp" TMP="$inkson_cache/tmp" TMPDIR="$inkson_cache/tmp"
export PYTHONPYCACHEPREFIX="$inkson_cache/pycache"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
