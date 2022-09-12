use super::engine_error;
use crate::prelude::{GlweCiphertextCount, GlweSize, PlaintextArrayEntity};

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextArrayEntity;

engine_error! {
    GlweCiphertextArrayTrivialEncryptionError for GlweCiphertextArrayTrivialEncryptionEngine @
    PlaintextCountMismatch => "The number of ciphertexts must divide the \
    plaintext count of the input array (the result of this division is the polynomial size)."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayTrivialEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<PlaintextArray>(
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        PlaintextArray: PlaintextArrayEntity,
    {
        if input.plaintext_count().0 % glwe_ciphertext_count.0 != 0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines trivially encrypting GLWE ciphertext array.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext array containing
/// the trivial encryption of the `input` plaintext array with the requested `glwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait GlweCiphertextArrayTrivialEncryptionEngine<PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
{
    /// Trivially encrypts a plaintext array into a GLWE ciphertext array.
    fn trivially_encrypt_glwe_ciphertext_array(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray,
    ) -> Result<CiphertextArray, GlweCiphertextArrayTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely trivially encrypts a plaintext array into a GLWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextArray,
    ) -> CiphertextArray;
}
