use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextArrayEntity, GlweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    GlweCiphertextArrayDiscardingEncryptionError for GlweCiphertextArrayDiscardingEncryptionEngine @
    GlweDimensionMismatch => "The GLWE dimensions of the key and the output ciphertext array must \
                              be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the output ciphertext array \
                               must be the same.",
    PlaintextCountMismatch => "The input plaintext array length and output ciphertext array \
                               capacity (poly size * length) must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextArrayDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextArray, CiphertextArray>(
        key: &SecretKey,
        output: &CiphertextArray,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextArray: PlaintextArrayEntity,
        CiphertextArray: GlweCiphertextArrayEntity,
    {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) GLWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext array
/// with the piece-wise encryptions of the `input` plaintext array, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::GlweCiphertextEncryptionEngine`)
pub trait GlweCiphertextArrayDiscardingEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: GlweCiphertextArrayEntity,
{
    /// Encrypts a GLWE ciphertext array .
    fn discard_encrypt_glwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextArray,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<(), GlweCiphertextArrayDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext array .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextArrayDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_glwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextArray,
        input: &PlaintextArray,
        noise: Variance,
    );
}
