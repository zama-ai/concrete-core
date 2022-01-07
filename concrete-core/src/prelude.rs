#![doc(hidden)]

// ----------------------------------------------------------------------------------- SPECIFICATION
pub use super::specification::engines::*;
pub use super::specification::entities::*;

// --------------------------------------------------------------------------------- DEFAULT BACKEND
#[cfg(feature = "backend_default")]
pub use super::backends::default::engines::*;
#[cfg(feature = "backend_default")]
pub use super::backends::default::entities::*;

// ------------------------------------------------------------------------------------ FFTW BACKEND
#[cfg(feature = "backend_fftw")]
pub use super::backends::fftw::engines::*;
#[cfg(feature = "backend_fftw")]
pub use super::backends::fftw::entities::*;

// ------------------------------------------------------------------------------------ CUDA BACKEND
#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
pub use super::backends::cuda::engines::*;
#[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
pub use super::backends::cuda::entities::*;

// ------------------------------------------------------------------------------------ OPTALYSYS BACKEND
#[cfg(feature = "backend_optalysys")]
pub use super::backends::optalysys::engines::*;
#[cfg(feature = "backend_optalysys")]
pub use super::backends::optalysys::entities::*;

// -------------------------------------------------------------------------------- COMMONS REEXPORT
// Expose concrete_commons types in the prelude. This avoids having to add concrete-commons as a
// dependency in crates built on top of concrete-core.
pub use concrete_commons::dispersion::*;
pub use concrete_commons::key_kinds::*;
pub use concrete_commons::parameters::*;
pub use concrete_commons::*;

// --------------------------------------------------------------------------------- CSPRNG REEXPORT
// Re-export the different seeders of the `concrete-csprng` crate, which are needed to construct
// default engines.
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use concrete_csprng::seeders::RdseedSeeder;
pub use concrete_csprng::seeders::Seeder;
#[cfg(feature = "seeder_unix")]
pub use concrete_csprng::seeders::UnixSeeder;
