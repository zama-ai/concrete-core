//! Fourier transform for polynomials.
//!
//! This module provides the tools to perform a fast product of two polynomials, reduced modulo
//! $X^N+1$, using the fast fourier transform provided by Optalysys.

#[cfg(test)]
mod tests;
mod twiddles;

mod transform;
pub use transform::*;

mod polynomial;
pub use polynomial::*;
