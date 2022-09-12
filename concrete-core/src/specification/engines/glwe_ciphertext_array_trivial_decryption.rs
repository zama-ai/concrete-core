use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextArrayEntity, PlaintextArrayEntity};

engine_error! {
    GlweCiphertextArrayTrivialDecryptionError for GlweCiphertextArrayTrivialDecryptionEngine @
}

/// A trait for engines trivially decrypting GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext array containing the
/// trivial decryption of the `input` ciphertext array.
///
/// # Formal Definition
///
/// see [here](../engines/trait.GlweCiphertextTrivialEncryptionEngine.html)
pub trait GlweCiphertextArrayTrivialDecryptionEngine<CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    CiphertextArray: GlweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts a GLWE ciphertext array into a plaintext array.
    fn trivially_decrypt_glwe_ciphertext_array(
        &mut self,
        input: &CiphertextArray,
    ) -> Result<PlaintextArray, GlweCiphertextArrayTrivialDecryptionError<Self::EngineError>>;

    /// Unsafely trivially decrypts a GLWE ciphertext array into a plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayTrivialDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        input: &CiphertextArray,
    ) -> PlaintextArray;
}
