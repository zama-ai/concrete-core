//! A module containing various backends implementing the `concrete` FHE scheme.

#[cfg(feature = "backend_default")]
pub mod default;

#[cfg(feature = "backend_fftw")]
pub mod fftw;
