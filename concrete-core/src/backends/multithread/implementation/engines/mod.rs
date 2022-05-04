//! A module containing the [engines](crate::specification::engines) exposed by the core backend.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use concrete_commons::parameters::{GlweSize, PolynomialSize};

use crate::backends::core::private::crypto::bootstrap::FourierBuffers;
use crate::backends::core::private::crypto::secret::generators::EncryptionRandomGenerator as ImplEncryptionRandomGenerator;
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;

#[derive(Debug)]
pub struct MultithreadError;

impl Display for MultithreadError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        panic!("No variant");
    }
}

impl Error for MultithreadError {}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct FourierBufferKey(pub PolynomialSize, pub GlweSize);

pub struct MultithreadEngine {
    encryption_generator: ImplEncryptionRandomGenerator,
    fourier_buffers_u32: BTreeMap<FourierBufferKey, FourierBuffers<u32>>,
    fourier_buffers_u64: BTreeMap<FourierBufferKey, FourierBuffers<u64>>,
}

impl MultithreadEngine {
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

impl AbstractEngineSeal for MultithreadEngine {}

impl AbstractEngine for MultithreadEngine {
    type EngineError = MultithreadError;

    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(MultithreadEngine {
            encryption_generator: ImplEncryptionRandomGenerator::new(None),
            fourier_buffers_u32: Default::default(),
            fourier_buffers_u64: Default::default(),
        })
    }
}

mod lwe_bootstrap_key_creation;
mod lwe_ciphertext_vector_discarding_bootstrap;
