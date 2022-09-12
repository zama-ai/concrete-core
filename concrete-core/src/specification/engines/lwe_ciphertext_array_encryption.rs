use super::engine_error;
use crate::prelude::Variance;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextArrayEntity, LweSecretKeyEntity, PlaintextArrayEntity,
};

engine_error! {
    LweCiphertextArrayEncryptionError for LweCiphertextArrayEncryptionEngine @
}

/// A trait for engines encrypting LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext array containing
/// the element-wise encryption of the `input` plaintext array, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweCiphertextEncryptionEngine`)
pub trait LweCiphertextArrayEncryptionEngine<SecretKey, PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Encrypts an LWE ciphertext array.
    fn encrypt_lwe_ciphertext_array(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> Result<CiphertextArray, LweCiphertextArrayEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an LWE ciphertext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextArray,
        noise: Variance,
    ) -> CiphertextArray;
}
