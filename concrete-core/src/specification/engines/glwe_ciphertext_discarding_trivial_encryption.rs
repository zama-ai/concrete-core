use super::engine_error;
use crate::prelude::PlaintextArrayEntity;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextDiscardingTrivialEncryptionError for GlweCiphertextDiscardingTrivialEncryptionEngine @
    MismatchedPolynomialSizeAndPlaintextArrayCount => "The input plaintext count must be the same\
                                                        as the output ciphertext polynomial size."
}

impl<EngineError: std::error::Error> GlweCiphertextDiscardingTrivialEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input: PlaintextArrayEntity, Output: GlweCiphertextEntity>(
        output: &Output,
        input: &Input,
    ) -> Result<(), Self> {
        if output.polynomial_size().0 != input.plaintext_count().0 {
            return Err(Self::MismatchedPolynomialSizeAndPlaintextArrayCount);
        }
        Ok(())
    }
}

/// A trait for engines trivially encrypting (discarding) GLWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills a GLWE ciphertext with the trivial
/// encryption of the `input` plaintext array with the requested `glwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextArray, Ciphertext>:
    AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
    Ciphertext: GlweCiphertextEntity,
{
    /// Trivially encrypts a plaintext array into a GLWE ciphertext.
    fn discard_trivially_encrypt_glwe_ciphertext(
        &mut self,
        output: &mut Ciphertext,
        input: &PlaintextArray,
    ) -> Result<(), GlweCiphertextDiscardingTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely trivially encrypts a plaintext array into a GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDiscardingTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &PlaintextArray,
    );
}
