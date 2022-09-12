use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextArrayEntity, LweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    LweCiphertextArrayDecryptionError for LweCiphertextArrayDecryptionEngine @
    LweDimensionMismatch => "The input and secret key LWE dimension must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextArray>(
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        CiphertextArray: LweCiphertextArrayEntity,
    {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing
/// the element-wise decryption of the `input` LWE ciphertext array under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDecryptionEngine`)
pub trait LweCiphertextArrayDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts an LWE ciphertext array.
    fn decrypt_lwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> Result<PlaintextArray, LweCiphertextArrayDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &CiphertextArray,
    ) -> PlaintextArray;
}
