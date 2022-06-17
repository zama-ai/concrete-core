use crate::commons::math::random::CompressionSeed;
use crate::specification::entities::markers::{
    KeyDistributionMarker, LweSeededCiphertextVectorKind,
};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};

/// A trait implemented by types embodying a seeded LWE ciphertext vector.
///
/// A seeded LWE ciphertext vector is associated with a
/// [`KeyDistribution`](`LweSeededCiphertextVectorEntity::KeyDistribution`) type, which conveys the
/// distribution of the secret key it was encrypted with.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::LweSeededCiphertextEntity`)
pub trait LweSeededCiphertextVectorEntity:
    AbstractEntity<Kind = LweSeededCiphertextVectorKind>
{
    /// The distribution of key the ciphertext was encrypted with.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the LWE dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of ciphertexts contained in the vector.
    fn lwe_ciphertext_count(&self) -> LweCiphertextCount;

    /// Returns the seed used to compress the LWE ciphertexts.
    fn compression_seed(&self) -> CompressionSeed;
}
