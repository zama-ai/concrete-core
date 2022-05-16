#!/usr/bin/env bash

# Stop on error
set -e

# We don't specify rust flags as the caller is the one who has to set them

# Find where this script is
CURR_DIR="$(dirname "$0")"
C_TESTS_BUILD_DIR="${CURR_DIR}/build/"

echo "Build the ffi libs"
cargo build --release --all-features -p concrete-ffi

echo "Clear the build dir"
rm -rf "${C_TESTS_BUILD_DIR}"

echo "Create the build dir for the C tests"
mkdir -p "${C_TESTS_BUILD_DIR}"

# Use pushd/popd to avoid keeping track of all dirs there are
pushd "${C_TESTS_BUILD_DIR}"

echo "Run cmake in Release mode to get test Makefile"
cmake .. -DCMAKE_BUILD_TYPE=RELEASE

echo "Build tests"
make -j "$(nproc)"

echo "Run tests"
# test is a built-in of bash so quote
make "test"

# Return to previous dir
popd
