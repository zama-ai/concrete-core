use crate::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweCiphertextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a GLWE ciphertext array.
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::GlweCiphertextEntity`)
pub trait GlweCiphertextArrayEntity: AbstractEntity<Kind = GlweCiphertextArrayKind> {
    /// Returns the GLWE dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of ciphertexts in the array.
    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount;
}
