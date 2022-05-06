//! An accelerated backend using `fftw`.

#[doc(hidden)]
pub mod private;

mod implementation;

pub use implementation::{engines, entities};
