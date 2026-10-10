#!/usr/bin/env bash
set -euo pipefail

# Native persistence tests use the production Secret Service backend. A CI
# runner needs a session bus and an unlocked, disposable login keyring.
command -v dbus-run-session >/dev/null
command -v gnome-keyring-daemon >/dev/null
command -v secret-tool >/dev/null
dbus-run-session -- bash -euo pipefail -c '
  printf "%s" "inkson-ci-scratch-keyring" |
    gnome-keyring-daemon --unlock --components=secrets
  printf "%s" "durable-value" | secret-tool store --label=inkson-ci-probe \
    service arkret.inkson-ci-probe account preflight
  test "$(secret-tool lookup service arkret.inkson-ci-probe account preflight)" = durable-value
  secret-tool clear service arkret.inkson-ci-probe account preflight
  cargo test "$@"
' bash "$@"
