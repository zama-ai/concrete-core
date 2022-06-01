//! A module containing general mathematical tools.

pub mod decomposition;
pub mod polynomial;
pub mod random;
pub mod tensor;
pub mod torus;

#[cfg(any(feature="backend_optalysys", feature="backend_fftw"))]
pub mod fft;
