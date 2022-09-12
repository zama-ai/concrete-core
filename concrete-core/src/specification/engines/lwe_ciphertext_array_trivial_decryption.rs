use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextArrayEntity, PlaintextArrayEntity};

use super::engine_error;

engine_error! {
    LweCiphertextArrayTrivialDecryptionError for LweCiphertextArrayTrivialDecryptionEngine @
}

/// A trait for engines trivially decrypting LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing the
/// trivial decryption of the `input` ciphertext array.
///
/// # Formal Definition
///
/// see [here](../engines/trait.LweCiphertextArrayTrivialEncryptionEngine.html)
pub trait LweCiphertextArrayTrivialDecryptionEngine<CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    CiphertextArray: LweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts a GLWE ciphertext array into a plaintext array.
    fn trivially_decrypt_lwe_ciphertext_array(
        &mut self,
        input: &CiphertextArray,
    ) -> Result<PlaintextArray, LweCiphertextArrayTrivialDecryptionError<Self::EngineError>>;

    /// Unsafely trivially decrypts an LWE ciphertext array into a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayTrivialDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        input: &CiphertextArray,
    ) -> PlaintextArray;
}
