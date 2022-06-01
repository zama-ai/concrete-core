//! Fourier transform for polynomials.
//!
//! This module provides the tools to perform a fast product of two polynomials, reduced modulo
//! $X^N+1$, using the fast fourier transform provided by Optalysys.

#[cfg(test)]
mod tests;

mod transform;
pub use transform::*;

mod polynomial;
pub use polynomial::*;

mod twiddles;
pub use twiddles::*;

pub use concrete_fftw::array::AlignedVec;

/// A complex number encoded over two `f64`.
pub type Complex64 = concrete_fftw::types::c64;
