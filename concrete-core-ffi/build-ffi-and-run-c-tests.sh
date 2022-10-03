#!/usr/bin/env bash

# Stop on error
set -e

function usage() {
    echo "$0: compile concrete-core-ffi and run tests"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to use for concrete-core-ffi compilation (with the leading +)"
    echo "--cargo-feature-string    The list of features to compile with, e.g. '--features=x86_64,backend_fft,backend_fft_serialization'"
    echo
}

RUST_TOOLCHAIN="+stable"
CARGO_FEATURES_STRING=

while [ -n "$1" ]
do
   case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--rust-toolchain" )
            shift
            RUST_TOOLCHAIN="$1"
            ;;

        "--cargo-features-string" )
            shift
            CARGO_FEATURES_STRING="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done


nproc_bin=nproc

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

# We don't specify rust flags as the caller is the one who has to set them

# Find where this script is
CURR_DIR="$(dirname "$0")"
C_TESTS_BUILD_DIR="${CURR_DIR}/build/"

echo "Build the ffi libs"
cargo "${RUST_TOOLCHAIN}" build --release $CARGO_FEATURES_STRING -p concrete-core-ffi

echo "Clear the build dir"
rm -rf "${C_TESTS_BUILD_DIR}"

echo "Create the build dir for the C tests"
mkdir -p "${C_TESTS_BUILD_DIR}"

# Use pushd/popd to avoid keeping track of all dirs there are
pushd "${C_TESTS_BUILD_DIR}"

echo "Run cmake in Release mode to get test Makefile"
cmake .. -DCMAKE_BUILD_TYPE=RELEASE

echo "Build tests"
make -j "$(${nproc_bin})"

echo "Run tests"
# test is a built-in of bash so quote
make "test"

# Return to previous dir
popd
