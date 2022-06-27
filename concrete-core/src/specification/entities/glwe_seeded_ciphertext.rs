use crate::commons::math::random::CompressionSeed;
use crate::specification::entities::markers::{GlweSeededCiphertextKind, KeyDistributionMarker};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

/// A trait implemented by types embodying a seeded GLWE ciphertext.
///
/// A seeded GLWE ciphertext is associated with a
/// [`KeyDistribution`](`GlweSeededCiphertextEntity::KeyDistribution`) type, which conveys the
/// distribution of the secret key it was encrypted with.
pub trait GlweSeededCiphertextEntity: AbstractEntity<Kind = GlweSeededCiphertextKind> {
    /// The distribution of the key the ciphertext was encrypted with.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
