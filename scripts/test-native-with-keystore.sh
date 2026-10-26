#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/build_env.sh"
exec bash "$(dirname "${BASH_SOURCE[0]}")/with-native-keystore.sh" cargo test --features app "$@"
