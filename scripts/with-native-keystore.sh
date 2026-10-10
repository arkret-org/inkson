#!/usr/bin/env bash
set -euo pipefail

# Execute the command and its children with a real, disposable Secret Service.
# Persistence tests still use the production backend and survive store reopen.
test "$#" -gt 0
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
  "$@"
' bash "$@"
