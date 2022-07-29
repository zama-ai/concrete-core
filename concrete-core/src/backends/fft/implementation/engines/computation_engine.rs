use concrete_commons::parameters::PolynomialSize;
use dyn_stack::DynStack;

use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use core::mem::MaybeUninit;

/// Error that can occur in the execution of FHE operations by the [`FftEngine`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FftError {
    UnsupportedPolynomialSize,
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FftError::UnsupportedPolynomialSize => f.write_str(
                "The Concrete-FFT backend only supports polynomials of sizes that are powers of two \
                    and greater than or equal to 32.",
            ),
        }
    }
}

impl std::error::Error for FftError {}

/// The main engine exposed by the Concrete-FFT backend.
pub struct FftEngine {
    memory: Vec<MaybeUninit<u8>>,
}

impl FftEngine {
    pub(crate) fn resize(&mut self, capacity: usize) {
        self.memory.resize_with(capacity, MaybeUninit::uninit);
    }

    pub(crate) fn stack(&mut self) -> DynStack<'_> {
        DynStack::new(&mut self.memory)
    }

    pub fn check_supported_size(polynomial_size: PolynomialSize) -> Result<(), FftError> {
        if polynomial_size.0.is_power_of_two() && polynomial_size.0 >= 32 {
            Ok(())
        } else {
            Err(FftError::UnsupportedPolynomialSize)
        }
    }
}

impl AbstractEngineSeal for FftEngine {}
impl AbstractEngine for FftEngine {
    type EngineError = FftError;
    type Parameters = ();

    fn new(_parameter: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftEngine { memory: Vec::new() })
    }
}
