use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextArrayEntity, LweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    LweCiphertextArrayDiscardingDecryptionError for LweCiphertextArrayDiscardingDecryptionEngine @
    LweDimensionMismatch => "The key and output LWE dimensions must be the same.",
    PlaintextCountMismatch => "The output plaintext count and the input ciphertext count must be \
                               the same."
}

impl<EngineError: std::error::Error> LweCiphertextArrayDiscardingDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextArray, PlaintextArray>(
        key: &SecretKey,
        output: &PlaintextArray,
        input: &CiphertextArray,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        CiphertextArray: LweCiphertextArrayEntity,
        PlaintextArray: PlaintextArrayEntity,
    {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if input.lwe_ciphertext_count().0 != output.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting (discarding) LWE ciphertext arrays.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext array
/// with the element-wise decryption of the `input` LWE ciphertext array under the `key` LWE secret
/// key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextDecryptionEngine`)
pub trait LweCiphertextArrayDiscardingDecryptionEngine<SecretKey, CiphertextArray, PlaintextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweCiphertextArrayEntity,
    PlaintextArray: PlaintextArrayEntity,
{
    /// Decrypts an LWE ciphertext array.
    fn discard_decrypt_lwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextArray,
        input: &CiphertextArray,
    ) -> Result<(), LweCiphertextArrayDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayDiscardingDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_decrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextArray,
        input: &CiphertextArray,
    );
}
