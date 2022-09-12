use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextArrayEntity, LweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    LweCiphertextArrayDiscardingEncryptionError for LweCiphertextArrayDiscardingEncryptionEngine @
    LweDimensionMismatch => "The key and output LWE dimensions must be the same.",
    PlaintextCountMismatch => "The input plaintext count and the output ciphertext count must be \
                               the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextArray, CiphertextArray>(
        key: &SecretKey,
        output: &CiphertextArray,
        input: &PlaintextArray,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        PlaintextArray: PlaintextArrayEntity,
        CiphertextArray: LweCiphertextArrayEntity,
    {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }

        Ok(())
    }
}

/// A trait for engines encrypting (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext array
/// with the element-wise encryption of the `input` plaintext array under the `key` LWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextEncryptionEngine`)
pub trait LweCiphertextArrayDiscardingEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Encrypts an LWE ciphertext array.
    fn discard_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextArray,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<(), LweCiphertextArrayDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encryprs an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextArray,
        input: &PlaintextArray,
        noise: Variance,
    );
}
