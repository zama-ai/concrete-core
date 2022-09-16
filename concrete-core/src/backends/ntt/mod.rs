//! An accelerated backend using the NTT.

#[doc(hidden)]
pub mod private;

mod implementation;

pub use implementation::{entities};
