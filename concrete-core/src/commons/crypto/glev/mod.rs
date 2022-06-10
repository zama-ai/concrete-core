//! Glev internal representation
//! A Glev is a vector of l GLWE ciphertexts encrypting the same
//! message M with a different scaling factor (q/B^l M), where B is a base log
//! In concrete-core the Glev type does not exist per se because it is not the best solution in 
//! terms of performance. Instead, we expose a level matrix, which corresponds to the GLWEs of a 
//! vector of Glev's for a specific decomposition level.
//! 
//! This level matrix is useful to represent GGSW ciphertexts (and bootstrap keys, which are 
//! vectors of GGSW ciphertexts), and relinearization keys

mod levels;
pub use levels::*;
