#!/usr/bin/env sh
# Run clippy over every target and every feature, and leave machine-readable
# evidence behind.
#
# This exists because the lint baseline went red and stayed red: nothing ran
# clippy, so thirteen findings accumulated across weeks of commits, and one of
# them was not a lint at all but a hard compile break that only
# `--all-features` reaches (`src/bin/inkson-wire.rs` is behind
# `required-features = ["spec-conformance"]`, so the default build never
# compiles it). Both halves matter:
#
#   * `--all-features` — otherwise feature-gated targets are never type-checked.
#   * `-D warnings` — a warning nobody fails on is a warning nobody fixes.
#
# Same output contract as `gate.sh`: the verdict goes to files, not to the
# terminal tail. Read `$INKSON_CLIPPY_GATE_DIR/summary.txt`.
#
# Usage:
#   scripts/clippy_gate.sh                 # whole workspace, all features
#   scripts/clippy_gate.sh -p inkson       # narrow re-run, same contract

set -eu

gate_dir="${INKSON_CLIPPY_GATE_DIR:-target/clippy-gate}"
target_dir="${INKSON_CLIPPY_GATE_TARGET_DIR:-target/clippy}"

mkdir -p "$gate_dir"
log="$gate_dir/clippy.log"
summary="$gate_dir/summary.txt"
status="$gate_dir/status.txt"

echo "clippy gate: target=$target_dir log=$log"

set +e
CARGO_TARGET_DIR="$target_dir" cargo clippy --locked \
    --workspace --all-targets --all-features "$@" -- -D warnings > "$log" 2>&1
code=$?
set -e

echo "$code" > "$status"

# Keep the lines a reviewer acts on: every diagnostic header and the source
# location that follows it.
grep -E '^(error(\[E[0-9]+\])?:|warning:|\s+--> )' "$log" > "$summary" || true

echo "--- $summary ---"
cat "$summary"
echo "--- exit $code (full log: $log) ---"
exit "$code"
