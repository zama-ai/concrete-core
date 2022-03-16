//! Relinearization keys.
//!
//! The relinearization operation allows to transform the result of a tensor product operation 
//! into a relinearized GLWE ciphertext whose key is the original key of the input GLWEs of the 
//! tensor product.

pub use standard::StandardGlweRelinearizationKey;

mod standard;

