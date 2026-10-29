#!/usr/bin/env bash
set -euo pipefail

# Execute the command and its children with a real, disposable Secret Service.
# Persistence tests still use the production backend and survive store reopen.
test "$#" -gt 0
command -v dbus-run-session >/dev/null
command -v gnome-keyring-daemon >/dev/null
command -v secret-tool >/dev/null
command -v gdbus >/dev/null
exec dbus-run-session -- python3 "$(dirname "${BASH_SOURCE[0]}")/native_keystore.py" -- "$@"
