use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextArrayEntity, GlweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    GlweCiphertextArrayDiscardingDecryptionError for GlweCiphertextArrayDiscardingDecryptionEngine @
    GlweDimensionMismatch => "The GLWE dimensions of the key and the input ciphertext array must \
                              be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the input ciphertext array must \
                               be the same.",
    PlaintextCountMismatch => "The input plaintext array length and input ciphertext array \
                               capacity (poly size * length) must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayDiscardingDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextArray, PlaintextArray>(
        key: &SecretKey,
        output: &PlaintextArray,
        input: &CiphertextArray,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        CiphertextArray: GlweCiphertextArrayEntity,
        PlaintextArray: PlaintextArrayEntity,
    {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0
            != (input.polynomial_size().0 * input.glwe_ciphertext_count().0)
        {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting (discarding) GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext array  
/// with the piece-wise decryptions of the `input` GLWE ciphertext array, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::GlweCiphertextDecryptionEngine`)
pub trait GlweCiphertextArrayDiscardingDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts a GLWE ciphertext array .
    fn discard_decrypt_glwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextArray,
        input: &CiphertextArray,
    ) -> Result<(), GlweCiphertextArrayDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext array .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayDiscardingDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_decrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextArray,
        input: &CiphertextArray,
    );
}
