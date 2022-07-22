#!/usr/bin/env bash

set -e

function usage() {
    echo "$0: install specified rust toolchain with clippy and rustfmt components at least"
    echo
    echo "--help                    Print this message"
    echo "--version                 The toolchain to install without the platform triplet"
    echo "--check                   Check that the toolchain is installed"
    echo
}

CHECK=0
TOOLCHAIN_VERSION=""

while [ -n "$1" ]
do
   case "$1" in
        "--help" | "-h" )
            usage
            exit 0
            ;;

        "--version" )
            shift
            TOOLCHAIN_VERSION="$1"
            ;;

        "--check" )
            CHECK=1
            ;;

        *)
            echo "Unknown param : $1"
            exit 1
            ;;
   esac
   shift
done

if [[ "${CHECK}" == "1" ]]; then
    rustup toolchain list | grep "${TOOLCHAIN_VERSION}" > /dev/null
else
    rustup toolchain install "${TOOLCHAIN_VERSION}"
    rustup component add rustfmt --toolchain "${TOOLCHAIN_VERSION}"
    rustup component add clippy --toolchain "${TOOLCHAIN_VERSION}"
fi
