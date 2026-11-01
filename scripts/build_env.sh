#!/usr/bin/env sh
# Preserve the caller environment and let Cargo resolve its paths.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
