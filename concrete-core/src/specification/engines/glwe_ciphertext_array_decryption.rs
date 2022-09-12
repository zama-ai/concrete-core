use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextArrayEntity, GlweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    GlweCiphertextArrayDecryptionError for GlweCiphertextArrayDecryptionEngine @
    GlweDimensionMismatch => "The key and input ciphertext array GLWE dimension must be the same.",
    PolynomialSizeMismatch => "The key and input ciphertext array polynomial size must be the \
                               same."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextArray>(
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        CiphertextArray: GlweCiphertextArrayEntity,
    {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing
/// the piece-wise decryptions of the `input` GLWE ciphertext array, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::GlweCiphertextDecryptionEngine`)
pub trait GlweCiphertextArrayDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts a GLWE ciphertext array.
    fn decrypt_glwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> Result<PlaintextArray, GlweCiphertextArrayDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a GLWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> PlaintextArray;
}
