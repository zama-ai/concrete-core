//! A module containing the cuda backend implementation.
//!
//! This module contains CUDA GPU implementations of some functions of the concrete scheme.
//! In particular, it makes it possible to execute bootstraps on an array of ciphertext arrays,
//! with an array of LUT and a bootstrap key as other inputs. To do so, the backend also
//! exposes functions to transfer data to and from the GPU, via conversion functions.

#[doc(hidden)]
pub mod private;

pub(crate) mod implementation;

pub use implementation::{engines, entities};
