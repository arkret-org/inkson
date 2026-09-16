#!/usr/bin/env sh
# Run the local test gate and leave machine-readable evidence behind.
#
# Inkson's suite is ~1800 tests. `cargo test` prints one line per test, so the
# failure summary lands at the very end of a log long enough that a terminal
# scrollback truncates it — the run looks inconclusive when it is not. Three
# things fix that here:
#
#   * `--quiet` — one character per test instead of one line.
#   * bounded `--jobs` — at full parallelism a low-memory or Windows runner
#     fails to mmap an rlib (`os error 1455`, the pagefile is too small), which
#     surfaces as a *test* failure and sends people chasing a bug that is not
#     there. One job removes it; raise `INKSON_GATE_JOBS` where there is
#     headroom.
#   * saved artifacts — the exit status and an extracted summary go to files, so
#     the verdict never depends on what is still on screen. Read
#     `$INKSON_GATE_DIR/summary.txt`, not the terminal tail.
#
# Runs with `--no-fail-fast` so one early failure does not hide the rest.
# Exits with cargo's status.
#
# Usage:
#   scripts/gate.sh                       # whole workspace
#   scripts/gate.sh --lib recovery        # narrow re-run, same output contract

set -eu

jobs="${INKSON_GATE_JOBS:-1}"
gate_dir="${INKSON_GATE_DIR:-target/gate}"
target_dir="${INKSON_GATE_TARGET_DIR:-target/test}"

mkdir -p "$gate_dir"
log="$gate_dir/test.log"
summary="$gate_dir/summary.txt"
status="$gate_dir/status.txt"

echo "gate: jobs=$jobs target=$target_dir log=$log"

set +e
CARGO_TARGET_DIR="$target_dir" cargo test --locked --quiet \
    --jobs "$jobs" --no-fail-fast "$@" > "$log" 2>&1
code=$?
set -e

echo "$code" > "$status"

# Keep only the lines a reviewer acts on: per-suite results, the failure roster
# and its entries, each failing test's header, and compiler errors.
#
# The roster-entry alternative matches an indented `path::to::test` and nothing
# else, so indented panic detail and cargo's own indented status lines stay
# out: both contain a space where a `::` segment would have to be.
grep -E '^(test result:|failures:|---- .* ----|error(\[E[0-9]+\])?:|    [A-Za-z_][A-Za-z0-9_]*(::[A-Za-z0-9_]+)+$)' "$log" \
    > "$summary" || true

echo "--- $summary ---"
cat "$summary"
echo "--- exit $code (full log: $log) ---"
exit "$code"
