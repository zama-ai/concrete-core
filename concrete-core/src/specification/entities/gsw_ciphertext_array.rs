use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GswCiphertextCount, LweDimension,
};
use crate::specification::entities::markers::GswCiphertextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GSW ciphertext array.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::GswCiphertextEntity`)
pub trait GswCiphertextArrayEntity: AbstractEntity<Kind = GswCiphertextArrayKind> {
    /// Returns the LWE dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of decomposition levels of the ciphertexts.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertexts.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the number of ciphertexts in the array.
    fn gsw_ciphertext_count(&self) -> GswCiphertextCount;
}
