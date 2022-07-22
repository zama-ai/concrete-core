use crate::cmd;
use crate::utils::{
    get_nightly_toolchain, get_target_arch_feature_for_core, get_target_arch_feature_for_doc,
    Environment,
};
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_DOC_KATEX: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "--html-in-header katex-header.html");
        env
    };
}

pub fn doc() -> Result<(), Error> {
    cmd!(<ENV_DOC_KATEX>
        &format!("cargo {} doc --features {} --no-deps --workspace --exclude concrete-cuda",
            get_nightly_toolchain()?,
            get_target_arch_feature_for_doc()?,
    ))
}

pub fn clippy() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} clippy --workspace --all-targets --exclude concrete-cuda --features {} -- \
        --no-deps -D warnings",
        get_nightly_toolchain()?,
        get_target_arch_feature_for_core()?
    ))
}

pub fn cuda_clippy() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} clippy -p concrete-core --features=backend_cuda -- --no-deps -D warnings",
        get_nightly_toolchain()?
    ))
}

pub fn fmt() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} fmt --all -- --check",
        get_nightly_toolchain()?
    ))
}
