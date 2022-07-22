use crate::utils::{get_build_toolchain, get_target_arch_feature_for_core, Environment};
use crate::{cmd, ENV_TARGET_NATIVE};
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_TARGET_SIMD: Environment = {
        let mut env = HashMap::new();
        env.insert(
            "RUSTFLAGS",
            "-Ctarget-feature=+aes,+rdseed,+sse2,+avx,+avx2",
        );
        env
    };
    static ref ENV_DOCTEST: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env
    };
    static ref ENV_DOCTEST_SIMD: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env.insert(
            "RUSTFLAGS",
            "-Ctarget-feature=+aes,+rdseed,+sse2,+avx,+avx2",
        );
        env
    };
    static ref ENV_DOCTEST_NATIVE: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env.insert("RUSTFLAGS", "-Ctarget-cpu=native");
        env
    };
}

pub mod debug {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} build --features {} --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn benches() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} build --features {} --benches --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn tests() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} test --features {} --no-run --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }
}

pub mod release {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} build --release --features {} --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn benches() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} build --release --features {} --benches --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn tests() -> Result<(), Error> {
        cmd!(&format!(
            "cargo {} test --release --features {} --no-run --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }
}

pub mod simd {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        let env: &Environment = if cfg!(target_os = "linux") {
            &ENV_TARGET_SIMD
        } else if cfg!(target_os = "macos") {
            &ENV_TARGET_NATIVE
        } else {
            unreachable!()
        };

        cmd!(<env> &format!(
            "cargo {} build --release --features {} --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn benches() -> Result<(), Error> {
        let env: &Environment = if cfg!(target_os = "linux") {
            &ENV_TARGET_SIMD
        } else if cfg!(target_os = "macos") {
            &ENV_TARGET_NATIVE
        } else {
            unreachable!()
        };

        cmd!(<env> &format!(
            "cargo {} build --release --features {} --benches --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }

    pub fn tests() -> Result<(), Error> {
        let env: &Environment = if cfg!(target_os = "linux") {
            &ENV_TARGET_SIMD
        } else if cfg!(target_os = "macos") {
            &ENV_TARGET_NATIVE
        } else {
            unreachable!()
        };

        cmd!(<env> &format!(
            "cargo {} test --release --features {} --no-run --workspace --exclude concrete-cuda",
            get_build_toolchain()?,
            get_target_arch_feature_for_core()?
        ))
    }
}
