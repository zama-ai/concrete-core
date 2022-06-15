use crate::utils::{get_nightly_toolchain, Environment};
use crate::{cmd, ENV_TARGET_NATIVE};
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_COVERAGE: Environment = {
        let mut env = HashMap::new();
        env.insert("CARGO_INCREMENTAL", "0");
        env.insert("RUSTFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env.insert("RUSTDOCFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env
    };
}

pub fn commons() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-commons")
}

pub fn core() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-core")
}

pub fn core_test() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-core-test")
}

pub fn csprng() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-csprng")
}

pub fn npe() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-npe")
}

pub fn ffi() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "./concrete-core-ffi/build-ffi-and-run-c-tests.sh")
}

pub fn crates() -> Result<(), Error> {
    commons()?;
    core()?;
    core_test()?;
    csprng()?;
    npe()?;
    ffi()
}

pub fn cov_crates() -> Result<(), Error> {
    cmd!(<ENV_COVERAGE>
        &format!("cargo {} test --release --no-fail-fast --all-features", get_nightly_toolchain()?))
}
