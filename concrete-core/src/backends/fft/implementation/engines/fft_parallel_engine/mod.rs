use crate::prelude::PolynomialSize;

use crate::prelude::FftEngine;
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use std::cell::RefCell;

thread_local! {
    pub static FFT_ENGINE: RefCell<FftEngine> = RefCell::new(FftEngine::new(()).unwrap());
}

/// Error that can occur in the execution of FHE operations by the [`FftParallelEngine`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FftParallelError {
    UnsupportedPolynomialSize,
}

impl core::fmt::Display for FftParallelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FftParallelError::UnsupportedPolynomialSize => f.write_str(
                "The Concrete-FFT backend only supports polynomials of sizes that are powers of two \
                    and greater than or equal to 32.",
            ),
        }
    }
}

impl std::error::Error for FftParallelError {}

impl FftParallelError {
    pub fn perform_fft_checks(polynomial_size: PolynomialSize) -> Result<(), FftParallelError> {
        if polynomial_size.0.is_power_of_two() && polynomial_size.0 >= 32 {
            Ok(())
        } else {
            Err(FftParallelError::UnsupportedPolynomialSize)
        }
    }
}

/// The main engine exposed by the Concrete-FFT backend.
pub struct FftParallelEngine {}

impl AbstractEngineSeal for FftParallelEngine {}
impl AbstractEngine for FftParallelEngine {
    type EngineError = FftParallelError;
    type Parameters = ();

    fn new(_parameter: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftParallelEngine {})
    }
}

mod lwe_ciphertext_vector_discarding_bootstrap;
