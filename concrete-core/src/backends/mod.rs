//! A module containing various backends implementing the `concrete` FHE scheme.

#[cfg(feature = "backend_default")]
pub mod default;

#[cfg(feature = "backend_fftw")]
pub mod fftw;

#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
pub mod cuda;

#[cfg(all(feature = "backend_optalysys", not(feature = "_ci_do_not_compile")))]
pub mod optalysys;
