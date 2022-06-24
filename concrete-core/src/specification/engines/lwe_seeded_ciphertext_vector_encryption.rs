use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweSecretKeyEntity, LweSeededCiphertextVectorEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweSeededCiphertextVectorEncryptionError for LweSeededCiphertextVectorEncryptionEngine @
}

/// A trait for engines encrypting seeded LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a seeded LWE ciphertext vector
/// containing the element-wise encryption of the `input` plaintext vector, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::engines::LweSeededCiphertextEncryptionEngine`)
pub trait LweSeededCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweSeededCiphertextVectorEntity<KeyDistribution = SecretKey::KeyDistribution>,
{
    /// Encrypts a seeded LWE ciphertext vector.
    fn encrypt_lwe_seeded_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<CiphertextVector, LweSeededCiphertextVectorEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a seeded LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededCiphertextVectorEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> CiphertextVector;
}
