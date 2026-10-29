#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/build_env.sh"
python3 -m unittest discover -s "$(dirname "${BASH_SOURCE[0]}")/tests" -p test_native_keystore.py

exec bash "$(dirname "${BASH_SOURCE[0]}")/with-native-keystore.sh" cargo test --features app "$@"
