use crate::utils::get_nightly_toolchain;
use crate::{cmd, format_latex_doc};
use std::io::Error;

pub fn format() -> Result<(), Error> {
    cmd!(&format!(
        "cargo {} fmt &&
                  clang-format -i concrete-cuda/cuda/include/* &&
                  clang-format -i concrete-cuda/cuda/src/*.cu &&
                  clang-format -i concrete-cuda/cuda/src/*.cuh &&
                  clang-format -i concrete-cuda/cuda/src/*/*.*",
        get_nightly_toolchain()?
    ))
}

pub fn format_latex_doc() -> Result<(), Error> {
    format_latex_doc::escape_underscore_in_latex_doc()
}
