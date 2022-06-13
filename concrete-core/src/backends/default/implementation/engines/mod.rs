//! A module containing the [engines](crate::specification::engines) exposed by the default backend.

use crate::commons::crypto::secret::generators::{
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use concrete_csprng::seeders::Seeder;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[cfg(not(feature = "backend_default_aesni"))]
type ActivatedRandomGenerator = concrete_csprng::generators::SoftwareRandomGenerator;
#[cfg(feature = "backend_default_aesni")]
type ActivatedRandomGenerator = concrete_csprng::generators::AesniRandomGenerator;

/// The error which can occur in the execution of FHE operations, due to the default implementation.
///
/// # Note:
///
/// There is currently no such case, as the default implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum DefaultError {}

impl Display for DefaultError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl Error for DefaultError {}

pub struct DefaultEngine {
    secret_generator: ImplSecretRandomGenerator<ActivatedRandomGenerator>,
    encryption_generator: ImplEncryptionRandomGenerator<ActivatedRandomGenerator>,
}

impl AbstractEngineSeal for DefaultEngine {}

impl AbstractEngine for DefaultEngine {
    type EngineError = DefaultError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(DefaultEngine {
            secret_generator: ImplSecretRandomGenerator::new(parameters.seed()),
            encryption_generator: ImplEncryptionRandomGenerator::new(
                parameters.seed(),
                parameters.as_mut(),
            ),
        })
    }
}

#[cfg(feature = "parallel")]
pub mod parallel {
    use std::error::Error;
    use std::fmt::{Display, Formatter};

    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::Seeder;

    use crate::commons::crypto::secret::generators::EncryptionRandomGenerator as ImplEncryptionRandomGenerator;
    use crate::specification::engines::sealed::AbstractEngineSeal;
    use crate::specification::engines::AbstractEngine;

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

    pub struct DefaultParallelEngine {
        pub(crate) encryption_generator: ImplEncryptionRandomGenerator<SoftwareRandomGenerator>,
    }

    impl AbstractEngineSeal for DefaultParallelEngine {}

    impl AbstractEngine for DefaultParallelEngine {
        type EngineError = DefaultParallelError;

        type Parameters = Box<dyn Seeder>;

        fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
            Ok(DefaultParallelEngine {
                encryption_generator: ImplEncryptionRandomGenerator::new(
                    parameters.seed(),
                    parameters.as_mut(),
                ),
            })
        }
    }
}

mod cleartext_creation;
mod cleartext_discarding_retrieval;
mod cleartext_retrieval;
mod cleartext_vector_creation;
mod cleartext_vector_discarding_retrieval;
mod cleartext_vector_retrieval;
mod destruction;
mod ggsw_ciphertext_scalar_discarding_encryption;
mod ggsw_ciphertext_scalar_encryption;
mod ggsw_ciphertext_scalar_trivial_encryption;
mod glwe_ciphertext_consuming_retrieval;
mod glwe_ciphertext_creation;
mod glwe_ciphertext_decryption;
mod glwe_ciphertext_discarding_decryption;
mod glwe_ciphertext_discarding_encryption;
mod glwe_ciphertext_discarding_trivial_encryption;
mod glwe_ciphertext_encryption;
mod glwe_ciphertext_trivial_decryption;
mod glwe_ciphertext_trivial_encryption;
mod glwe_ciphertext_vector_decryption;
mod glwe_ciphertext_vector_discarding_decryption;
mod glwe_ciphertext_vector_discarding_encryption;
mod glwe_ciphertext_vector_encryption;
mod glwe_ciphertext_vector_trivial_decryption;
mod glwe_ciphertext_vector_trivial_encryption;
mod glwe_ciphertext_vector_zero_encryption;
mod glwe_ciphertext_zero_encryption;
mod glwe_secret_key_creation;
mod glwe_to_lwe_secret_key_transmutation;
mod lwe_bootstrap_key_creation;
mod lwe_ciphertext_cleartext_discarding_multiplication;
mod lwe_ciphertext_cleartext_fusing_multiplication;
mod lwe_ciphertext_consuming_retrieval;
mod lwe_ciphertext_creation;
mod lwe_ciphertext_decryption;
mod lwe_ciphertext_discarding_addition;
mod lwe_ciphertext_discarding_decryption;
mod lwe_ciphertext_discarding_encryption;
mod lwe_ciphertext_discarding_extraction;
mod lwe_ciphertext_discarding_keyswitch;
mod lwe_ciphertext_discarding_opposite;
mod lwe_ciphertext_discarding_subtraction;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_fusing_addition;
mod lwe_ciphertext_fusing_opposite;
mod lwe_ciphertext_fusing_subtraction;
mod lwe_ciphertext_plaintext_discarding_addition;
mod lwe_ciphertext_plaintext_discarding_subtraction;
mod lwe_ciphertext_plaintext_fusing_addition;
mod lwe_ciphertext_plaintext_fusing_subtraction;
mod lwe_ciphertext_trivial_decryption;
mod lwe_ciphertext_trivial_encryption;
mod lwe_ciphertext_vector_decryption;
mod lwe_ciphertext_vector_discarding_addition;
mod lwe_ciphertext_vector_discarding_affine_transformation;
mod lwe_ciphertext_vector_discarding_decryption;
mod lwe_ciphertext_vector_discarding_encryption;
mod lwe_ciphertext_vector_discarding_subtraction;
mod lwe_ciphertext_vector_encryption;
mod lwe_ciphertext_vector_fusing_addition;
mod lwe_ciphertext_vector_fusing_subtraction;
mod lwe_ciphertext_vector_glwe_ciphertext_discarding_packing_keyswitch;
mod lwe_ciphertext_vector_trivial_decryption;
mod lwe_ciphertext_vector_trivial_encryption;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
mod lwe_keyswitch_key_creation;
mod lwe_secret_key_creation;
mod lwe_to_glwe_secret_key_transmutation;
mod packing_keyswitch_key_creation;
mod plaintext_creation;
mod plaintext_discarding_retrieval;
mod plaintext_retrieval;
mod plaintext_vector_creation;
mod plaintext_vector_discarding_retrieval;
mod plaintext_vector_retrieval;
