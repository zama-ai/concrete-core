use super::engine_error;
use crate::prelude::{GlweSize, PlaintextArrayEntity};

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextTrivialEncryptionError for GlweCiphertextTrivialEncryptionEngine @
}

/// A trait for engines trivially encrypting GLWE ciphertext.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing the
/// trivial encryption of the `input` plaintext array with the requested `glwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait GlweCiphertextTrivialEncryptionEngine<PlaintextArray, Ciphertext>:
    AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
    Ciphertext: GlweCiphertextEntity,
{
    /// Trivially encrypts a plaintext array into a GLWE ciphertext.
    fn trivially_encrypt_glwe_ciphertext(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextArray,
    ) -> Result<Ciphertext, GlweCiphertextTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely creates the trivial GLWE encryption of the plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextTrivialEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextArray,
    ) -> Ciphertext;
}
