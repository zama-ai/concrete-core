use crate::commons::math::random::CompressionSeed;

use crate::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::specification::entities::markers::GgswSeededCiphertextKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded GGSW ciphertext.
///
/// # Formal Definition
///
/// # Seeded GGSW Ciphertext
///
/// A seeded GGSW ciphertext is an encryption of a polynomial plaintext.
/// It is a [`seeded vector`](`crate::specification::entities::GlweSeededCiphertextVectorEntity`)
/// of GLWE ciphertexts.
/// It is a generalization of both GSW ciphertexts and RGSW ciphertexts.
///
/// See the [`GGSW ciphertext`](`crate::specification::entities::GgswCiphertextEntity`) for more
/// information.
pub trait GgswSeededCiphertextEntity: AbstractEntity<Kind = GgswSeededCiphertextKind> {
    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;

    /// Returns the number of decomposition levels of the ciphertext.
    fn decomposition_level_count(&self) -> DecompositionLevelCount;

    /// Returns the logarithm of the base used in the ciphertext.
    fn decomposition_base_log(&self) -> DecompositionBaseLog;

    /// Returns the compression seed used to generate the mask of the various GLWE ciphertexts
    /// during encryption.
    fn compression_seed(&self) -> CompressionSeed;
}
