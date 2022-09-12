use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use crate::backends::fftw::private::math::fft::ALLOWED_POLY_SIZE;
use crate::prelude::{GlweSize, PolynomialSize};

use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;

/// The error which can occur in the execution of FHE operations, due to the fftw implementation.
#[derive(Debug)]
pub enum FftwError {
    UnsupportedPolynomialSize,
}

impl Display for FftwError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FftwError::UnsupportedPolynomialSize => {
                write!(
                    f,
                    "The Fftw Backend only supports polynomials of size: 512, \
                1024, 2048, 4096, 8192, 16384."
                )
            }
        }
    }
}

impl Error for FftwError {}

impl FftwError {
    pub fn perform_fftw_checks(polynomial_size: PolynomialSize) -> Result<(), Self> {
        if !ALLOWED_POLY_SIZE.contains(&polynomial_size.0) {
            return Err(FftwError::UnsupportedPolynomialSize);
        }
        Ok(())
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct FourierBufferKey(pub PolynomialSize, pub GlweSize);

/// The main engine exposed by the fftw backend.
pub struct FftwEngine {
    // We attach Fourier buffers to the Fftw Engine:
    // Each time a bootstrap key is created, a check is made to see whether those buffers exist for
    // the required polynomial and GLWE sizes. If the buffers already exist, they are simply used
    // when it comes to computing FFTs. If they don't exist already, they are allocated. In this
    // way we avoid re-allocating those buffers every time an FFT or iFFT is performed.
    fourier_buffers_u32: BTreeMap<FourierBufferKey, FourierBuffers<u32>>,
    fourier_buffers_u64: BTreeMap<FourierBufferKey, FourierBuffers<u64>>,
}

impl FftwEngine {
    pub(crate) fn get_fourier_u32_buffer(
        &mut self,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> &mut FourierBuffers<u32> {
        let buffer_key = FourierBufferKey(poly_size, glwe_size);
        self.fourier_buffers_u32
            .entry(buffer_key)
            .or_insert_with(|| FourierBuffers::for_params(poly_size, glwe_size))
    }

    pub(crate) fn get_fourier_u64_buffer(
        &mut self,
        poly_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> &mut FourierBuffers<u64> {
        let buffer_key = FourierBufferKey(poly_size, glwe_size);
        self.fourier_buffers_u64
            .entry(buffer_key)
            .or_insert_with(|| FourierBuffers::for_params(poly_size, glwe_size))
    }
}

impl AbstractEngineSeal for FftwEngine {}

impl AbstractEngine for FftwEngine {
    type EngineError = FftwError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftwEngine {
            fourier_buffers_u32: Default::default(),
            fourier_buffers_u64: Default::default(),
        })
    }
}

mod ggsw_ciphertext_conversion;
mod ggsw_ciphertext_discarding_conversion;
mod glwe_ciphertext_conversion;
mod glwe_ciphertext_ggsw_ciphertext_discarding_external_product;
mod glwe_ciphertext_ggsw_ciphertext_external_product;
mod glwe_ciphertexts_ggsw_ciphertext_fusing_cmux;
mod lwe_bootstrap_key_conversion;
mod lwe_ciphertext_discarding_bit_extraction;
mod lwe_ciphertext_discarding_bootstrap;
mod lwe_ciphertext_vector_discarding_circuit_bootstrap_boolean_vertical_packing;
