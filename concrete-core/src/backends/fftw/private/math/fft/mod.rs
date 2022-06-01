//! Fourier transform for polynomials.
//!
//! This module provides the tools to perform a fast product of two polynomials, reduced modulo
//! $X^N+1$, using the fast fourier transform.

#[cfg(test)]
mod tests;

mod plan;

mod polynomial;
pub use polynomial::*;

mod transform;
pub use transform::*;

pub use concrete_fftw::array::AlignedVec;

pub(crate) const ALLOWED_POLY_SIZE: [usize; 8] = [128, 256, 512, 1024, 2048, 4096, 8192, 16384];
