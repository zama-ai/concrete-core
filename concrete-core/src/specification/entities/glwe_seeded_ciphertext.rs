use crate::commons::math::random::CompressionSeed;
use crate::prelude::{GlweDimension, PolynomialSize};
use crate::specification::entities::markers::GlweSeededCiphertextKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded GLWE ciphertext.
pub trait GlweSeededCiphertextEntity: AbstractEntity<Kind = GlweSeededCiphertextKind> {
    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the compression seed used to generate the mask of the LWE ciphertext during
    /// encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
