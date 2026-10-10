#!/usr/bin/env bash
set -euo pipefail

exec bash "$(dirname "${BASH_SOURCE[0]}")/with-native-keystore.sh" cargo test "$@"
