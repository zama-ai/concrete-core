#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: generates a release of concrete-core-ffi using the given toolchain and features"
    echo
    echo "--help                    Print this message"
    echo "--rust-toolchain          The toolchain to use starting with a +"
    echo "--features-string         A string containing all the features to enable"
    echo "--rust-build-dir          The location where the rust build artifacts are to be found"
    echo "--output-release-dir      The directory to store the result of the release"
    echo "--sha256-sum-filename     The filename (no path) of the file to dump the sha256 digests"
    echo "--github-env-file         The file to store new env variables for github actions"
    echo "--release-flavor          The kind of release, e.g. linux_amd64"
    echo
}

# Some mac OS releases don't have the -f flag for readlink to canonicalize...
function abspath() {
    if [[ $(echo "$1" | awk '/^\//') == "$1" ]]; then
        echo "$1"
    else
        echo "$(pwd)/$1"
    fi
}


RUST_TOOLCHAIN="+stable"
CARGO_FEATURES=""
OUTPUT_RELEASE_DIR="core-ffi-release-dir"
RUST_BUILD_DIR="target/release/"
SHA256_SUM_FILE="sha256.txt"
GITHUB_ENV_FILE="/dev/null"
RELEASE_FLAVOR="unknown"

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

        "--features-string" )
            shift
            CARGO_FEATURES="$1"
            ;;

        "--rust-build-dir" )
            shift
            RUST_BUILD_DIR="$1"
            ;;

        "--output-release-dir" )
            shift
            OUTPUT_RELEASE_DIR="$1"
            ;;

        "--sha256-sum-out-file" )
            shift
            SHA256_SUM_FILE="$1"
            ;;

        "--github-env-file" )
            shift
            GITHUB_ENV_FILE="$1"
            ;;

        "--release-flavor" )
            shift
            RELEASE_FLAVOR="$1"
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

# Canonicalize path
OUTPUT_RELEASE_DIR="$(abspath "${OUTPUT_RELEASE_DIR}")"
RUST_BUILD_DIR="$(abspath "${RUST_BUILD_DIR}")"

cargo "${RUST_TOOLCHAIN}" build --release \
${CARGO_FEATURES} \
-p concrete-core-ffi

echo "Build artifacts:"

# Check the build output
ls "${RUST_BUILD_DIR}"

# Use cargo metadata to emit all metadata in json form, format version is recommended
# for compatibility. Then use the jq (r: raw string, c: condensed) filter which does:
# Iterate over json["packages"] as array, select the package named "concrete-core-ffi" and
# output its version
CONCRETE_CORE_FFI_VERSION="$(cargo metadata --format-version 1 |
jq -rc '.packages[] | select(.name=="concrete-core-ffi") | .version')"

echo "concrete-core-ffi version: ${CONCRETE_CORE_FFI_VERSION}"

# Use the output release dir and create a raw artifacts dir in it
mkdir -p "${OUTPUT_RELEASE_DIR}"
RAW_ARTIFACTS_DIR="${OUTPUT_RELEASE_DIR}/raw_artifacts"
mkdir -p "${RAW_ARTIFACTS_DIR}"

echo "TO_UPLOAD=${OUTPUT_RELEASE_DIR}/*" >> "${GITHUB_ENV_FILE}"

# Copy the build artifacts to the raw_artifacts dir
# Hard code the names of the files we want to archive
cp "${RUST_BUILD_DIR}/concrete-core-ffi.h" "${RAW_ARTIFACTS_DIR}/"
cp "${RUST_BUILD_DIR}/libconcrete_core_ffi.a" "${RAW_ARTIFACTS_DIR}/"

if [[ -f "${RUST_BUILD_DIR}/libconcrete_core_ffi.so" ]]; then
    cp "${RUST_BUILD_DIR}/libconcrete_core_ffi.so" "${RAW_ARTIFACTS_DIR}/"
fi
if [[ -f "${RUST_BUILD_DIR}/libconcrete_core_ffi.dylib" ]]; then
    cp "${RUST_BUILD_DIR}/libconcrete_core_ffi.dylib" "${RAW_ARTIFACTS_DIR}/"
fi

OUTPUT_TARBALL="${OUTPUT_RELEASE_DIR}/concrete-core-ffi_${CONCRETE_CORE_FFI_VERSION}_${RELEASE_FLAVOR}.tar.gz"
OUTPUT_ZIP="${OUTPUT_RELEASE_DIR}/concrete-core-ffi_${CONCRETE_CORE_FFI_VERSION}_${RELEASE_FLAVOR}.zip"

# Goto OUTPUT_RELEASE_DIR first then RAW_ARTIFACTS_DIR
pushd "${OUTPUT_RELEASE_DIR}"
pushd "${RAW_ARTIFACTS_DIR}"

# Create archives
echo "Creating tarball..."
tar -cvzf "${OUTPUT_TARBALL}" ./*

echo "Creating zip archive..."
zip -r "${OUTPUT_ZIP}" ./*

# Return to OUTPUT_RELEASE_DIR
popd
# Create the sha256 for both archives
find . -maxdepth 1 -type f -iname "concrete-core-ffi*" | \
sort | xargs shasum -a 256 -b > "${SHA256_SUM_FILE}"

# Remove the copies to make our lives easier when packaging artifacts
rm -rf "${RAW_ARTIFACTS_DIR}"

ls
