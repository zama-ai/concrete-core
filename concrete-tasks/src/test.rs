use crate::utils::{
    get_build_toolchain, get_nightly_toolchain, get_target_arch_feature_for_core, Environment,
};
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

pub fn core() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo {} test --profile release-debug-asserts --no-fail-fast --features {} -p concrete-core",
        get_build_toolchain()?,
        get_target_arch_feature_for_core()?
    ))
}

pub fn core_test() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo {} test --profile release-debug-asserts --no-fail-fast --features {} -p concrete-core-test",
        get_build_toolchain()?,
        get_target_arch_feature_for_core()?,
    ))
}

pub fn csprng() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo {} test --profile release-debug-asserts --no-fail-fast --features {} -p concrete-csprng",
        get_build_toolchain()?,
        get_target_arch_feature_for_core()?
    ))
}

pub fn npe() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo {} test --profile release-debug-asserts --no-fail-fast -p concrete-npe",
        get_build_toolchain()?,
    ))
}

pub fn ffi() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!(
        "./concrete-core-ffi/build-ffi-and-run-c-tests.sh --rust-toolchain '{}' \
        --cargo-features-string '--features {}'",
        get_build_toolchain()?,
        get_target_arch_feature_for_core()?,
    ))
}

pub fn cuda_test() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo test --profile release-debug-asserts --no-fail-fast \
        --features=backend_cuda --features {} -p concrete-core-test -- cuda:: --test-threads 1",
        get_target_arch_feature_for_core()?
    ))
}

pub fn cuda_core_test() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE>
        &format!("cargo test --profile release-debug-asserts -p concrete-core \
        --features=backend_cuda --features {} -- backends::cuda --test-threads 1",
        get_target_arch_feature_for_core()?
    ))
}

pub fn crates() -> Result<(), Error> {
    core()?;
    core_test()?;
    csprng()?;
    npe()?;
    ffi()
}

pub fn cuda() -> Result<(), Error> {
    cuda_test()?;
    cuda_core_test()
}

pub fn cov_crates() -> Result<(), Error> {
    cmd!(<ENV_COVERAGE>
        &format!("cargo {} test --release --no-fail-fast --all-features", get_nightly_toolchain()?))
}
