use crate::{cmd, format_latex_doc};
use std::io::Error;

pub fn format() -> Result<(), Error> {
    cmd!("cargo +nightly fmt")
}

pub fn format_latex_doc() -> Result<(), Error> {
    format_latex_doc::escape_underscore_in_latex_doc()
}
