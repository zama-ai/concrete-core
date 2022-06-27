use crate::commons::math::random::CompressionSeed;
use crate::specification::entities::markers::{
    GlweSeededCiphertextVectorKind, KeyDistributionMarker,
};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};

/// A trait implemented by types embodying a seeded GLWE ciphertext vector.
///
/// A GLWE seeded ciphertext vector is associated with a
/// [`KeyDistribution`](`GlweSeededCiphertextVectorEntity::KeyDistribution`) type, which conveys the
/// distribution of the secret key it was encrypted with.
///
/// **Remark:** GLWE ciphertexts generalize LWE ciphertexts by definition, however in this library,
/// GLWE ciphertext entities do not generalize LWE ciphertexts, i.e., polynomial size cannot be 1.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::GlweSeededCiphertextEntity`)
pub trait GlweSeededCiphertextVectorEntity:
    AbstractEntity<Kind = GlweSeededCiphertextVectorKind>
{
    /// The distribution of the key the ciphertext was encrypted with.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the GLWE dimension of the ciphertexts.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertexts.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of ciphertexts in the vector.
    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
