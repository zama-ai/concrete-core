use super::engine_error;
use crate::prelude::{GlweCiphertextCount, Variance};
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextArrayEntity, GlweSecretKeyEntity};

engine_error! {
    GlweCiphertextArrayZeroEncryptionError for GlweCiphertextArrayZeroEncryptionEngine @
    NullCiphertextCount => "The ciphertext count must be greater than zero."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayZeroEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(count: GlweCiphertextCount) -> Result<(), Self> {
        if count.0 == 0 {
            return Err(Self::NullCiphertextCount);
        }
        Ok(())
    }
}

/// A trait for engines encrypting zero in GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext array containing
/// encryptions of zeros, under the `key` secret key.
///
/// # Formal Definition
///
/// This generates an array of [`GLWE
/// encryption`](`crate::specification::engines::GlweCiphertextEncryptionEngine`) of zero.
pub trait GlweCiphertextArrayZeroEncryptionEngine<SecretKey, CiphertextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
{
    /// Encrypts zero in a GLWE ciphertext array.
    fn zero_encrypt_glwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<CiphertextArray, GlweCiphertextArrayZeroEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts zero in a GLWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayZeroEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn zero_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> CiphertextArray;
}
