use crate::cmd;
use crate::utils::{get_nightly_toolchain, Environment};
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
    cmd!(<ENV_DOC_KATEX> &format!("cargo {} doc --features=doc --no-deps --workspace --exclude concrete-cuda", get_nightly_toolchain()?))
}

pub fn clippy() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} clippy --all-targets --all-features -- --no-deps -D warnings",
        get_nightly_toolchain()?
    ))
}

pub fn fmt() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} fmt --all -- --check",
        get_nightly_toolchain()?
    ))
}
