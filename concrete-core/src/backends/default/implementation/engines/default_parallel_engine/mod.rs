use crate::commons::crypto::secret::generators::{
    DeterministicSeeder as ImplDeterministicSeeder,
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
#[cfg(feature = "backend_default_generator_x86_64_aesni")]
use concrete_csprng::generators::AesniRandomGenerator;
#[cfg(not(feature = "backend_default_generator_x86_64_aesni"))]
use concrete_csprng::generators::SoftwareRandomGenerator;
use concrete_csprng::seeders::Seeder;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the default
/// parallel implementation.
///
/// # Note:
///
/// There is currently no such case, as the default parallel implementation is not expected to
/// undergo major issues unrelated to FHE.
#[derive(Debug)]
pub enum DefaultParallelError {}

impl Display for DefaultParallelError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl Error for DefaultParallelError {}

#[cfg(feature = "backend_default_generator_x86_64_aesni")]
type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(not(feature = "backend_default_generator_x86_64_aesni"))]
type ActivatedRandomGenerator = SoftwareRandomGenerator;

pub struct DefaultParallelEngine {
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`ImplEncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: ImplEncryptionRandomGenerator<ActivatedRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`ImplEncryptionRandomGenerator`] to encrypt seeded types.
    seeder: ImplDeterministicSeeder<ActivatedRandomGenerator>,
}

impl AbstractEngineSeal for DefaultParallelEngine {}

impl AbstractEngine for DefaultParallelEngine {
    type EngineError = DefaultParallelError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let mut deterministic_seeder =
            ImplDeterministicSeeder::<ActivatedRandomGenerator>::new(parameters.seed());

        Ok(DefaultParallelEngine {
            encryption_generator: ImplEncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            seeder: deterministic_seeder,
        })
    }
}

mod lwe_bootstrap_key_creation;
mod lwe_seeded_bootstrap_key_creation;
