use crate::commons::math::random::CompressionSeed;
use crate::prelude::{LweCiphertextCount, LweDimension};
use crate::specification::entities::markers::LweSeededCiphertextArrayKind;
use crate::specification::entities::AbstractEntity;

/// A trait implemented by types embodying a seeded LWE ciphertext array.
///
/// # Formal Definition
///
/// cf [`here`](`crate::specification::entities::LweSeededCiphertextEntity`)
pub trait LweSeededCiphertextArrayEntity:
    AbstractEntity<Kind = LweSeededCiphertextArrayKind>
{
    /// Returns the LWE dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of ciphertexts contained in the array.
    fn lwe_ciphertext_count(&self) -> LweCiphertextCount;

    /// Returns the seed used to compress the LWE ciphertexts.
    fn compression_seed(&self) -> CompressionSeed;
}
