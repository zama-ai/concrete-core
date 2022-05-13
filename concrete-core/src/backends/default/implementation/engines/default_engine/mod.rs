use crate::commons::crypto::secret::generators::{
    DeterministicSeeder as ImplDeterministicSeeder,
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
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

/// The error which can occur in the execution of FHE operations, due to the default implementation.
///
/// # Note:
///
/// There is currently no such case, as the default implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum DefaultError {
    FloatEncoderMessageOutsideInterval,
    FloatEncoderNullPrecision,
    FloatEncoderMinMaxOrder,
    FloatEncoderNullRadius,
}

impl Display for DefaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            DefaultError::FloatEncoderMessageOutsideInterval => write!(
                f,
                "Tried to encode a message outside float encoder interval."
            ),
            DefaultError::FloatEncoderNullPrecision => write!(
                f,
                "Tried to create a float encoder with zero bits of precision."
            ),
            DefaultError::FloatEncoderMinMaxOrder => write!(
                f,
                "Tried to create a float encoder whose min bound is larger than max bound."
            ),
            DefaultError::FloatEncoderNullRadius => {
                write!(f, "Tried to create a float encoder with null radius.")
            }
        }
    }
}

impl Error for DefaultError {}

#[cfg(feature = "backend_default_generator_x86_64_aesni")]
type ActivatedRandomGenerator = AesniRandomGenerator;
#[cfg(not(feature = "backend_default_generator_x86_64_aesni"))]
type ActivatedRandomGenerator = SoftwareRandomGenerator;

pub struct DefaultEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: ImplSecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`ImplEncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: ImplEncryptionRandomGenerator<ActivatedRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`ImplEncryptionRandomGenerator`] to encrypt seeded types.
    seeder: ImplDeterministicSeeder<ActivatedRandomGenerator>,
}
impl AbstractEngineSeal for DefaultEngine {}

impl AbstractEngine for DefaultEngine {
    type EngineError = DefaultError;

    type Parameters = Box<dyn Seeder>;

    fn new(mut parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        let mut deterministic_seeder =
            ImplDeterministicSeeder::<ActivatedRandomGenerator>::new(parameters.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        // So parameters is moved in seeder after the calls to seed and the potential calls when it
        // is passed as_mut in ImplEncryptionRandomGenerator::new
        Ok(DefaultEngine {
            secret_generator: ImplSecretRandomGenerator::new(deterministic_seeder.seed()),
            encryption_generator: ImplEncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            seeder: deterministic_seeder,
        })
    }
}

mod cleartext_creation;
mod cleartext_discarding_retrieval;
mod cleartext_encoding;
mod cleartext_retrieval;
mod cleartext_vector_creation;
mod cleartext_vector_discarding_retrieval;
mod cleartext_vector_encoding;
mod cleartext_vector_retrieval;
mod encoder_creation;
mod encoder_vector_creation;
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
mod glwe_seeded_ciphertext_encryption;
mod glwe_seeded_ciphertext_to_glwe_ciphertext_transformation;
mod glwe_seeded_ciphertext_vector_encryption;
mod glwe_seeded_vector_to_glwe_ciphertext_vector_transformation;
mod glwe_to_lwe_secret_key_transformation;
mod lwe_bootstrap_key_construction;
mod lwe_bootstrap_key_consuming_retrieval;
mod lwe_bootstrap_key_creation;
mod lwe_bootstrap_key_discarding_conversion;
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
mod lwe_ciphertext_vector_glwe_ciphertext_discarding_private_functional_packing_keyswitch;
mod lwe_ciphertext_vector_trivial_decryption;
mod lwe_ciphertext_vector_trivial_encryption;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
mod lwe_functional_packing_keyswitch_key_creation;
mod lwe_keyswitch_key_creation;
mod lwe_private_functional_packing_keyswitch_key_creation;
mod lwe_secret_key_creation;
mod lwe_seeded_bootstrap_key_creation;
mod lwe_seeded_bootstrap_key_to_lwe_bootstrap_key_transformation;
mod lwe_seeded_ciphertext_encryption;
mod lwe_seeded_ciphertext_vector_encryption;
mod lwe_seeded_ciphertext_vector_to_lwe_ciphertext_vector_transformation;
mod lwe_seeded_keyswitch_key_creation;
mod lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_transformation;
mod lwe_seeded_to_lwe_ciphertext_transformation;
mod lwe_to_glwe_secret_key_transformation;
mod packing_keyswitch_key_creation;
mod plaintext_creation;
mod plaintext_decoding;
mod plaintext_discarding_retrieval;
mod plaintext_retrieval;
mod plaintext_vector_creation;
mod plaintext_vector_decoding;
mod plaintext_vector_discarding_retrieval;
mod plaintext_vector_retrieval;
