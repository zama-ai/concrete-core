use crate::prelude::{LweCiphertextCount, LweDimension};
use crate::specification::entities::markers::LweCiphertextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE ciphertext array.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::LweCiphertextEntity`)
pub trait LweCiphertextArrayEntity: AbstractEntity<Kind = LweCiphertextArrayKind> {
    /// Returns the LWE dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of ciphertexts contained in the array.
    fn lwe_ciphertext_count(&self) -> LweCiphertextCount;
}
