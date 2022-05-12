//! A module containing the [engines](crate::specification::engines) exposed by the aesni backend.

use std::error::Error;
use std::fmt::{Display, Formatter};

use concrete_csprng::generators::AesniRandomGenerator;
use concrete_csprng::seeders::Seeder;

use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;

/// The error which can occur in the execution of FHE operations, due to the aesni implementation.
///
/// # Note:
///
/// There is currently no such case, as the aesni implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum AesniError {}

impl Display for AesniError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl Error for AesniError {}

pub struct AesniEngine {
    secret_generator: ImplSecretRandomGenerator<AesniRandomGenerator>,
    encryption_generator: ImplEncryptionRandomGenerator<AesniRandomGenerator>,
}

impl AbstractEngineSeal for AesniEngine {}

impl AbstractEngine for AesniEngine {
    type EngineError = AesniError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(AesniEngine {
            secret_generator: ImplSecretRandomGenerator::new(parameters.seed()),
            encryption_generator: ImplEncryptionRandomGenerator::new(
                parameters.seed(),
                parameters.as_mut(),
            ),
        })
    }
}

mod glwe_secret_key_creation;
mod lwe_bootstrap_key_creation;
mod lwe_keyswitch_key_creation;
mod lwe_secret_key_creation;
mod ggsw_ciphertext_scalar_discarding_encryption;
mod ggsw_ciphertext_scalar_encryption;
mod glwe_ciphertext_discarding_encryption;
mod glwe_ciphertext_encryption;
mod glwe_ciphertext_vector_discarding_encryption;
mod glwe_ciphertext_vector_encryption;
mod glwe_ciphertext_vector_zero_encryption;
mod glwe_ciphertext_zero_encryption;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_vector_encryption;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
