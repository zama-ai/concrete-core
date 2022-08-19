//! A module containing all the necessary tools to generate the pre-execution context for the
//! fixtures.
//!
//! Generating the pre-execution context (engine inputs) for the fixtures can be tricky. We have to
//! generate entities of the right type, which are also functionally compatible (encoded with the
//! same secret key for instance). The [`Maker`] type is the main entry point to context setup,
//! which is a two-step process:
//!
//! + First, we use the [`Maker`] type to generate _prototypical_ entities, sometimes using _raw_
//! inputs. These abstract entities allow to ensure that we create compatible pieces of data. To
//! manipulate prototypical entities, one can rely on the `Prototypes*` traits of the
//! [`prototyping`] module, which are all implemented by the [`Maker`] type.
//! + Then we can use the [`Maker`] type again to _synthesize_ entities from prototypical ones.
//! These entities have the actual type expected by the engine and can be used to execute the engine
//! itself. To synthesize entities, one can rely on the `Synthesizes*` traits of the
//! [`synthesizing`] module, which are all implemented by the [`Maker`] type.
//!
//! Of course, we can also go in the reverse direction by _unsynthesizing_ entities into
//! prototypical ones, and extracting _raw_ outputs.
//! Also, the fixture developer should ensure that
//! the entities are destroyed after the execution of the engine. This is actually only
//! necessary for views entities, to avoid memory leak, but we don't have any simple way to track
//! which entities have view implementations, so we have to call functions to destroy the data.
//! This can be done by the
//! [`Maker`] instance and the `Synthesizes*` traits, which contains functions to destroy data
//! (which are empty for all entities that are not actually views).
use crate::raw::generation::RawUnsignedIntegers;
use concrete_core::prelude::{AbstractEngine, DefaultEngine, DefaultParallelEngine};
use concrete_csprng::seeders::UnixSeeder;

pub mod prototypes;
pub mod prototyping;
pub mod synthesizing;

/// A trait for marker types representing key distributions managed in `concrete_core`.
pub trait KeyDistributionMarker: 'static {}

/// A type representing binary key distribution
pub struct BinaryKeyDistribution;
impl KeyDistributionMarker for BinaryKeyDistribution {}

/// A type representing ternary key distribution
pub struct TernaryKeyDistribution;
impl KeyDistributionMarker for TernaryKeyDistribution {}

/// A type representing Gaussian key distribution
pub struct GaussianKeyDistribution;
impl KeyDistributionMarker for GaussianKeyDistribution {}

/// A trait for marker type representing integer precision managed in `concrete_core`.
pub trait IntegerPrecision {
    type Raw: RawUnsignedIntegers;
}

/// A type representing the 32 bits precision for integers.
pub struct Precision32;
impl IntegerPrecision for Precision32 {
    type Raw = u32;
}

/// A type representing the 64 bits precision for integers.
pub struct Precision64;
impl IntegerPrecision for Precision64 {
    type Raw = u64;
}

/// The central structure used to generate the pre-execution context for all the fixtures.
///
/// This structure contains the necessary tools to:
///
/// + Convert back and forth between raw types and prototypical plaintexts / cleartexts.
/// + Manipulate prototypical entities, to generate compatible prototypical inputs for tests.
/// + Convert back and forth between prototypical entities and actual entity types used in the
/// fixture.
pub struct Maker {
    default_engine: DefaultEngine,
    default_parallel_engine: DefaultParallelEngine,
    #[cfg(feature = "backend_fftw")]
    fftw_engine: concrete_core::backends::fftw::engines::FftwEngine,
    #[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
    cuda_engine: concrete_core::backends::cuda::engines::CudaEngine,
}

impl Default for Maker {
    fn default() -> Self {
        Maker {
            default_engine: DefaultEngine::new(Box::new(UnixSeeder::new(0))).unwrap(),
            default_parallel_engine: DefaultParallelEngine::new(Box::new(UnixSeeder::new(0)))
                .unwrap(),
            #[cfg(feature = "backend_fftw")]
            fftw_engine: concrete_core::backends::fftw::engines::FftwEngine::new(()).unwrap(),
            #[cfg(all(feature = "backend_cuda", not(feature = "_ci_do_not_compile")))]
            cuda_engine: concrete_core::backends::cuda::engines::CudaEngine::new(()).unwrap(),
        }
    }
}
