use super::engine_error;
use crate::prelude::{LweCiphertextCount, Variance};
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextArrayEntity, LweSecretKeyEntity};

engine_error! {
    LweCiphertextArrayZeroEncryptionError for LweCiphertextArrayZeroEncryptionEngine @
    NullCiphertextCount => "The ciphertext count must be greater than zero."
}

impl<EngineError: std::error::Error> LweCiphertextArrayZeroEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(count: LweCiphertextCount) -> Result<(), Self> {
        if count.0 == 0 {
            return Err(Self::NullCiphertextCount);
        }
        Ok(())
    }
}

/// A trait for engines encrypting zero in LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext array containing
/// encryptions of zeros, under the `key` secret key.
///
/// # Formal Definition
///
/// This generates an array of [`LWE encryption`]
/// (`crate::specification::engines::LweCiphertextEncryptionEngine`) of zero.
pub trait LweCiphertextArrayZeroEncryptionEngine<SecretKey, CiphertextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Encrypts zeros in an LWE ciphertext array.
    fn zero_encrypt_lwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<CiphertextArray, LweCiphertextArrayZeroEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts zeros in an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayZeroEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn zero_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> CiphertextArray;
}
