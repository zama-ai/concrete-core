//! Module mirroring the `concrete-core` source structure which provides the corresponding `C` FFI.

#[cfg(feature = "backend_cuda")]
pub mod cuda;
#[cfg(feature = "backend_default")]
pub mod default;
#[cfg(feature = "backend_fftw")]
pub mod fftw;
