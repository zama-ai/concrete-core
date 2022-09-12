use super::engine_error;
use crate::prelude::LweSize;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextArrayEntity, PlaintextArrayEntity};

engine_error! {
    LweCiphertextArrayTrivialEncryptionError for LweCiphertextArrayTrivialEncryptionEngine @
}

/// A trait for engines trivially encrypting LWE ciphertext arrays.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext array
/// containing the element-wise trivial encryption of the `input` plaintext array,
/// with the requested `lwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait LweCiphertextArrayTrivialEncryptionEngine<PlaintextArray, CiphertextArray>:
    AbstractEngine
where
    PlaintextArray: PlaintextArrayEntity,
    CiphertextArray: LweCiphertextArrayEntity,
{
    /// Trivially encrypts an LWE ciphertext array.
    fn trivially_encrypt_lwe_ciphertext_array(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray,
    ) -> Result<CiphertextArray, LweCiphertextArrayTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely creates the trivial LWE encryption of the plaintext array.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextArrayTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_encrypt_lwe_ciphertext_array_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextArray,
    ) -> CiphertextArray;
}
