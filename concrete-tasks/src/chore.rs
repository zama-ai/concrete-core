use crate::utils::get_nightly_toolchain;
use crate::{cmd, format_latex_doc};
use std::io::Error;

pub fn format() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} fmt --features=_ci_do_not_compile",
        get_nightly_toolchain()?
    ))
}

pub fn format_latex_doc() -> Result<(), Error> {
    format_latex_doc::escape_underscore_in_latex_doc()
}
