#!/usr/bin/env bash
set -euo pipefail

python3 -m unittest discover -s "$(dirname "${BASH_SOURCE[0]}")/tests" -p test_native_keystore.py

exec bash "$(dirname "${BASH_SOURCE[0]}")/with-native-keystore.sh" cargo test "$@"
