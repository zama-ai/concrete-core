use super::engine_error;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweSecretKeyEntity, GlweSeededCiphertextEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    GlweSeededCiphertextEncryptionError for GlweSeededCiphertextEncryptionEngine @
    PlaintextCountMismatch => "The plaintext count of the input vector and the key polynomial size \
    must be the same."
}

impl<EngineError: std::error::Error> GlweSeededCiphertextEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector>(
        key: &SecretKey,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if key.polynomial_size().0 != input.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting seeded GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing the
/// encryption of the `input` plaintext vetor under the `key` secret key.
///
/// # Formal Definition
///
/// ## GLWE Encryption
///
/// TODO
pub trait GlweSeededCiphertextEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    Ciphertext: GlweSeededCiphertextEntity<KeyDistribution = SecretKey::KeyDistribution>,
{
    /// Encrypts a seeded GLWE ciphertext.
    fn encrypt_glwe_seeded_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<Ciphertext, GlweSeededCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSeededCiphertextEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_glwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Ciphertext;
}
