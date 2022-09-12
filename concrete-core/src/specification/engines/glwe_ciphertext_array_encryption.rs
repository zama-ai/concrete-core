use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextArrayEntity, GlweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    GlweCiphertextArrayEncryptionError for GlweCiphertextArrayEncryptionEngine @
    PlaintextCountMismatch => "The key polynomial size must divide the plaintext count of the input \
                               array."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextArray>(
        key: &SecretKey,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextArray: PlaintextArrayEntity,
    {
        if (input.plaintext_count().0 % key.polynomial_size().0) != 0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext array containing
/// the piece-wise encryptions of the `input` plaintext array, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::GlweCiphertextEncryptionEngine`)
pub trait GlweCiphertextArrayEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
{
    /// Encrypts a GLWE ciphertext array.
    fn encrypt_glwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<CiphertextArray, GlweCiphertextArrayEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> CiphertextArray;
}
