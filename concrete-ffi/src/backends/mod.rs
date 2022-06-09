//! Module mirroring the `concrete-core` source structure which provides the corresponding `C` FFI.

#[cfg(feature = "backend_default")]
pub mod default;
#[cfg(feature = "backend_fftw")]
pub mod fftw;

use concrete_core::prelude::RandomGeneratorImplementation as CoreRandomGeneratorImplementation;

use std::convert::From;

#[repr(C)]
pub enum RandomGeneratorImplementation {
    #[cfg(feature = "generator_x86_64_aesni")]
    Aesni,
    Software,
}

impl From<RandomGeneratorImplementation> for CoreRandomGeneratorImplementation {
    fn from(from: RandomGeneratorImplementation) -> Self {
        match from {
            #[cfg(feature = "generator_x86_64_aesni")]
            RandomGeneratorImplementation::Aesni => CoreRandomGeneratorImplementation::Aesni,
            RandomGeneratorImplementation::Software => CoreRandomGeneratorImplementation::Software,
        }
    }
}
